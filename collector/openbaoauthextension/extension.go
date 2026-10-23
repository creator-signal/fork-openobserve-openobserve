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
	}, func(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
		config := cfg.(*Config)
		if err := config.Validate(); err != nil {
			return nil, err
		}
		return &authenticator{cfg: *config, now: time.Now}, nil
	}, component.StabilityLevelAlpha)
}

type session struct {
	token     string
	expires   time.Time
	renewable bool
}
type state struct {
	session session
	secret  string
	fetched time.Time
}
type authenticator struct {
	cfg       Config
	now       func() time.Time
	mu        sync.RWMutex
	refreshMu sync.Mutex
	state     state
	cancel    context.CancelFunc
	done      chan struct{}
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
	if response.StatusCode != 200 || response.ContentLength > maxBody {
		return errUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		return errUnavailable
	}
	if json.Unmarshal(data, output) != nil {
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
	return session{response.Auth.Token, a.now().Add(time.Duration(response.Auth.Lease) * time.Second), response.Auth.Renewable}, nil
}
func (a *authenticator) fetch(ctx context.Context, client *http.Client, token string) (string, error) {
	var response struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := a.request(ctx, client, "GET", a.cfg.RecordPath, token, nil, &response); err != nil {
		return "", err
	}
	fields := response.Data.Data
	secret := fields["automation_ingest_token"]
	if len(fields) != 2 || fields["schema"] != "creator-signal.openobserve-collector/v1" || len(secret) < 32 || len(secret) > 256 || strings.ContainsAny(secret, " \t\r\n") {
		return "", errUnavailable
	}
	for _, char := range secret {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return "", errUnavailable
		}
	}
	return secret, nil
}
func (a *authenticator) refresh(ctx context.Context) error {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	client, transport, err := a.client()
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	a.mu.RLock()
	previous := a.state
	a.mu.RUnlock()
	token := previous.session
	if token.token == "" || !token.expires.After(a.now().Add(2*a.cfg.RefreshInterval)) {
		token, err = a.login(ctx, client, token)
		if err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.state.session = token
	a.mu.Unlock()
	secret, err := a.fetch(ctx, client, token.token)
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
		secret, err = a.fetch(ctx, client, token.token)
	}
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.state = state{token, secret, a.now()}
	a.mu.Unlock()
	return nil
}
func (a *authenticator) Start(ctx context.Context, _ component.Host) error {
	if err := a.cfg.Validate(); err != nil {
		return err
	}
	if err := a.refresh(ctx); err != nil {
		return err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		ticker := time.NewTicker(a.cfg.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				_ = a.refresh(lifetime)
			}
		}
	}()
	return nil
}
func (a *authenticator) Shutdown(ctx context.Context) error {
	if a.cancel == nil {
		return nil
	}
	a.cancel()
	select {
	case <-a.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	a.mu.Lock()
	a.state = state{}
	a.mu.Unlock()
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
	t.auth.mu.RUnlock()
	if current.secret == "" || t.auth.now().Sub(current.fetched) >= t.auth.cfg.MaxStale {
		return nil, errUnavailable
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.SetBasicAuth(username, current.secret)
	return t.base.RoundTrip(clone)
}
