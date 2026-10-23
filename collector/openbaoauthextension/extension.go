// Package openbaoauthextension authenticates the OTLP HTTP exporter using a
// certificate-authenticated, ingestion-only OpenBao KV record held in memory.
package openbaoauthextension

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.opentelemetry.io/otel/metric"
)

var errConfig = errors.New("openbaoauth: invalid configuration")
var errUnavailable = errors.New("openbaoauth: credentials unavailable")
var errDenied = errors.New("openbaoauth: authentication denied")
var errDestination = errors.New("openbaoauth: exporter destination denied")

const maxBody = 65536
const username = "creator-signal-ingest"

type Config struct {
	Address         string        `mapstructure:"address"`
	Role            string        `mapstructure:"cert_role"`
	CAFile          string        `mapstructure:"ca_file"`
	CertFile        string        `mapstructure:"cert_file"`
	KeyFile         string        `mapstructure:"key_file"`
	RecordPath      string        `mapstructure:"record_path"`
	ExportEndpoint  string        `mapstructure:"export_endpoint"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
	MaxStale        time.Duration `mapstructure:"max_stale"`
}

func safeOrigin(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, errConfig
	}
	return u, nil
}
func (c *Config) Validate() error {
	origin, err := safeOrigin(c.Address)
	if err != nil || (origin.Path != "" && origin.Path != "/") {
		return errConfig
	}
	export, err := safeOrigin(c.ExportEndpoint)
	if err != nil || export.Path == "" || strings.HasSuffix(export.Path, "/") {
		return errConfig
	}
	for _, part := range strings.Split(export.Path, "/")[1:] {
		if part == "" || part == "." || part == ".." {
			return errConfig
		}
	}
	if c.Role == "" || strings.Trim(c.Role, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return errConfig
	}
	if !strings.Contains(c.RecordPath, "/data/") || !strings.HasSuffix(c.RecordPath, "/collector") || strings.HasPrefix(c.RecordPath, "/") || strings.Trim(c.RecordPath, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/ ") != "" || strings.Contains(c.RecordPath, " ") {
		return errConfig
	}
	for _, part := range strings.Split(c.RecordPath, "/") {
		if part == "" || part == "." || part == ".." {
			return errConfig
		}
	}
	if c.RefreshInterval < 5*time.Second || c.RefreshInterval > 5*time.Minute || c.MaxStale < c.RefreshInterval || c.MaxStale > 15*time.Minute {
		return errConfig
	}
	if !filepath.IsAbs(c.CAFile) || !filepath.IsAbs(c.CertFile) || !filepath.IsAbs(c.KeyFile) {
		return errConfig
	}
	return nil
}
func NewFactory() extension.Factory {
	return extension.NewFactory(component.MustNewType("openbaoauth"), func() component.Config {
		return &Config{RefreshInterval: time.Minute, MaxStale: 5 * time.Minute}
	}, func(_ context.Context, settings extension.Settings, cfg component.Config) (extension.Extension, error) {
		config := cfg.(*Config)
		if err := config.Validate(); err != nil {
			return nil, err
		}
		a := &authenticator{cfg: *config, now: time.Now}
		if settings.MeterProvider != nil {
			if err := a.registerMetrics(settings.MeterProvider); err != nil {
				return nil, err
			}
		}
		return a, nil
	}, component.StabilityLevelAlpha)
}

type session struct {
	token     string
	client    *http.Client
	expires   time.Time
	renewable bool
	renewAt   time.Time
}
type state struct {
	session session
	secret  string
	fetched time.Time
	version uint64
}
type authenticator struct {
	cfg          Config
	now          func() time.Time
	mu           sync.RWMutex
	refreshMu    sync.Mutex
	state        state
	cancel       context.CancelFunc
	done         chan struct{}
	wake         chan struct{}
	stopped      bool
	lifecycle    lifecycle
	registration metric.Registration
}

type lifecycle struct {
	LastSuccess         time.Time
	ConsecutiveFailures int64
	RefreshFailures     int64
	AuthRefreshes       int64
	Rotations           int64
	NextRetry           time.Time
	LastTrigger         time.Time
}

func retryDelay(failures int64) time.Duration {
	shift := min(max(failures-1, 0), 5)
	ceiling := min(10*time.Second<<shift, 5*time.Minute)
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}

func (a *authenticator) registerMetrics(provider metric.MeterProvider) error {
	meter := provider.Meter("openbaoauth")
	last, err := meter.Int64ObservableGauge("openbao_last_success_timestamp_seconds")
	if err != nil {
		return err
	}
	failures, err := meter.Int64ObservableGauge("openbao_consecutive_failures")
	if err != nil {
		return err
	}
	age, err := meter.Float64ObservableGauge("openbao_snapshot_age_seconds")
	if err != nil {
		return err
	}
	ready, err := meter.Int64ObservableGauge("openbao_ready")
	if err != nil {
		return err
	}
	total, err := meter.Int64ObservableCounter("openbao_refresh_failures")
	if err != nil {
		return err
	}
	triggered, err := meter.Int64ObservableCounter("openbao_auth_refreshes")
	if err != nil {
		return err
	}
	rotations, err := meter.Int64ObservableCounter("openbao_rotations")
	if err != nil {
		return err
	}
	a.registration, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if !a.lifecycle.LastSuccess.IsZero() {
			observer.ObserveInt64(last, a.lifecycle.LastSuccess.Unix())
		}
		observer.ObserveInt64(failures, a.lifecycle.ConsecutiveFailures)
		observer.ObserveInt64(total, a.lifecycle.RefreshFailures)
		observer.ObserveInt64(triggered, a.lifecycle.AuthRefreshes)
		observer.ObserveInt64(rotations, a.lifecycle.Rotations)
		var healthy int64
		if !a.state.fetched.IsZero() {
			elapsed := a.now().Sub(a.state.fetched)
			observer.ObserveFloat64(age, max(0, elapsed.Seconds()))
			if !a.stopped && elapsed < a.cfg.MaxStale && a.state.secret != "" {
				healthy = 1
			}
		}
		observer.ObserveInt64(ready, healthy)
		return nil
	}, last, failures, age, ready, total, triggered, rotations)
	return err
}

func (a *authenticator) triggerAuthRefresh() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.stopped || a.lifecycle.NextRetry.After(now) || (!a.lifecycle.LastTrigger.IsZero() && now.Sub(a.lifecycle.LastTrigger) < 5*time.Second) {
		return false
	}
	a.lifecycle.LastTrigger = now
	a.lifecycle.AuthRefreshes++
	if a.wake != nil {
		select {
		case a.wake <- struct{}{}:
		default:
		}
	}
	return true
}

func (a *authenticator) delay() time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.lifecycle.NextRetry.IsZero() {
		return max(0, a.lifecycle.NextRetry.Sub(a.now()))
	}
	if a.state.session.token != "" {
		return max(0, min(a.cfg.RefreshInterval, a.state.session.renewAt.Sub(a.now())))
	}
	return a.cfg.RefreshInterval
}

var _ extensionauth.HTTPClient = (*authenticator)(nil)

func (a *authenticator) String() string   { return "OpenBaoAuth([REDACTED])" }
func (a *authenticator) GoString() string { return a.String() }

func (a *authenticator) client() (*http.Client, *http.Transport, error) {
	ca, err := os.ReadFile(a.cfg.CAFile)
	if err != nil {
		return nil, nil, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, errConfig
	}
	pair, err := tls.LoadX509KeyPair(a.cfg.CertFile, a.cfg.KeyFile)
	if err != nil {
		return nil, nil, errConfig
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport, nil
}

func (a *authenticator) request(ctx context.Context, client *http.Client, method, route, token string, body any, output any) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return errConfig
		}
		payload = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.Address, "/")+"/v1/"+route, payload)
	if err != nil {
		return errConfig
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return errUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return errDenied
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > maxBody {
		return errUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		return errUnavailable
	}
	if output != nil && json.Unmarshal(data, output) != nil {
		return errUnavailable
	}
	return nil
}
func (a *authenticator) login(ctx context.Context, client *http.Client, old session) (session, error) {
	var response struct {
		Auth struct {
			Token     string `json:"client_token"`
			Lease     uint64 `json:"lease_duration"`
			Renewable bool   `json:"renewable"`
		} `json:"auth"`
	}
	renewed := false
	if old.renewable && old.expires.After(a.now()) {
		renewed = a.request(ctx, client, "POST", "auth/token/renew-self", old.token, map[string]string{}, &response) == nil
	}
	if !renewed {
		if err := a.request(ctx, client, "POST", "auth/cert/login", "", map[string]string{"name": a.cfg.Role}, &response); err != nil {
			return session{}, err
		}
	}
	if response.Auth.Token == "" || strings.ContainsAny(response.Auth.Token, "\r\n") || response.Auth.Lease == 0 || response.Auth.Lease > 86400 {
		return session{}, errDenied
	}
	ttl := time.Duration(response.Auth.Lease) * time.Second
	return session{token: response.Auth.Token, client: client, expires: a.now().Add(ttl), renewable: response.Auth.Renewable, renewAt: a.now().Add(ttl * 2 / 3)}, nil
}
func (a *authenticator) fetch(ctx context.Context, client *http.Client, token string) (string, uint64, error) {
	var response struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version uint64 `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := a.request(ctx, client, "GET", a.cfg.RecordPath, token, nil, &response); err != nil {
		return "", 0, err
	}
	fields := response.Data.Data
	secret := fields["automation_ingest_token"]
	if response.Data.Metadata.Version == 0 || len(fields) != 2 || fields["schema"] != "creator-signal.openobserve-collector/v1" || len(secret) < 32 || len(secret) > 256 || strings.ContainsAny(secret, " \t\r\n") {
		return "", 0, errUnavailable
	}
	for _, char := range secret {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return "", 0, errUnavailable
		}
	}
	return secret, response.Data.Metadata.Version, nil
}
func (a *authenticator) refresh(ctx context.Context) (result error) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.mu.RLock()
	stopped := a.stopped
	a.mu.RUnlock()
	if stopped {
		return errUnavailable
	}
	defer func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if result == nil {
			a.lifecycle.LastSuccess = a.now()
			a.lifecycle.ConsecutiveFailures = 0
			a.lifecycle.NextRetry = time.Time{}
		} else {
			a.lifecycle.ConsecutiveFailures++
			a.lifecycle.RefreshFailures++
			a.lifecycle.NextRetry = a.now().Add(retryDelay(a.lifecycle.ConsecutiveFailures))
		}
	}()
	client, transport, err := a.client()
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	a.mu.RLock()
	previous := a.state
	a.mu.RUnlock()
	token := previous.session
	if token.token == "" || !token.renewAt.After(a.now()) || !token.expires.After(a.now()) {
		token, err = a.login(ctx, client, token)
		if err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.state.session = token
	a.mu.Unlock()
	secret, version, err := a.fetch(ctx, client, token.token)
	if errors.Is(err, errDenied) {
		a.mu.Lock()
		a.state.session = session{}
		a.mu.Unlock()
		token, err = a.login(ctx, client, session{})
		if err != nil {
			return err
		}
		a.mu.Lock()
		a.state.session = token
		a.mu.Unlock()
		secret, version, err = a.fetch(ctx, client, token.token)
	}
	if err != nil {
		return err
	}
	// A replaced certificate can authenticate reads before the token renews.
	// Revoke with this latest verified transport, not the older login pair.
	token.client = client
	a.mu.Lock()
	if a.state.version != 0 && a.state.version != version {
		a.lifecycle.Rotations++
	}
	a.state = state{session: token, secret: secret, fetched: a.now(), version: version}
	a.mu.Unlock()
	return nil
}
func (a *authenticator) Start(ctx context.Context, _ component.Host) error {
	if err := a.cfg.Validate(); err != nil {
		return err
	}
	if err := a.refresh(ctx); err != nil {
		return errors.Join(err, a.Shutdown(context.Background()))
	}
	lifetime, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	a.mu.Lock()
	a.wake = make(chan struct{}, 1)
	a.mu.Unlock()
	go func() {
		defer close(a.done)
		for {
			timer := time.NewTimer(a.delay())
			select {
			case <-lifetime.Done():
				timer.Stop()
				return
			case <-a.wake:
				timer.Stop()
			case <-timer.C:
			}
			a.mu.RLock()
			blocked := a.lifecycle.NextRetry.After(a.now())
			a.mu.RUnlock()
			if !blocked {
				a.refresh(lifetime)
			} // Every outcome updates lifecycle telemetry.
		}
	}()
	return nil
}
func (a *authenticator) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return nil
	}
	a.stopped = true
	a.mu.Unlock()
	if a.registration != nil {
		defer a.registration.Unregister()
	}
	if a.cancel != nil {
		a.cancel()
		select {
		case <-a.done:
		case <-ctx.Done():
			a.mu.Lock()
			a.state = state{}
			a.mu.Unlock()
			return errUnavailable
		}
	}
	a.mu.Lock()
	token := a.state.session
	a.state = state{}
	a.mu.Unlock()
	if token.token != "" {
		// Cached authenticated transport keeps shutdown independent of file I/O.
		if token.client == nil {
			return errUnavailable
		}
		defer token.client.CloseIdleConnections()
		return a.request(ctx, token.client, "POST", "auth/token/revoke-self", token.token, map[string]string{}, nil)
	}
	return nil
}

type scopedTransport struct {
	auth *authenticator
	base http.RoundTripper
}

func (a *authenticator) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	return &scopedTransport{a, base}, nil
}
func (t *scopedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	allowed, err := safeOrigin(t.auth.cfg.ExportEndpoint)
	if err != nil {
		return nil, errDestination
	}
	target := request.URL
	if target.Scheme != allowed.Scheme || !strings.EqualFold(target.Host, allowed.Host) || target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.RawPath != "" || request.Method != http.MethodPost {
		return nil, errDestination
	}
	permitted := false
	for _, signal := range []string{"logs", "metrics", "traces"} {
		if target.Path == allowed.Path+"/v1/"+signal {
			permitted = true
		}
	}
	if !permitted {
		return nil, errDestination
	}
	t.auth.mu.RLock()
	current := t.auth.state
	stopped := t.auth.stopped
	t.auth.mu.RUnlock()
	if stopped || current.secret == "" || t.auth.now().Sub(current.fetched) >= t.auth.cfg.MaxStale {
		return nil, errUnavailable
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.SetBasicAuth(username, current.secret)
	response, err := t.base.RoundTrip(clone)
	if err == nil && response != nil && (response.StatusCode == 401 || response.StatusCode == 403) {
		t.auth.triggerAuthRefresh()
	}
	return response, err
}
