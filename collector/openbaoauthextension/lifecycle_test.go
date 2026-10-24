package openbaoauthextension

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type readinessHost struct{ events []*componentstatus.Event }

func (h *readinessHost) GetExtensions() map[component.ID]component.Component { return nil }
func (h *readinessHost) Report(event *componentstatus.Event)                 { h.events = append(h.events, event) }

func TestReadinessTransitionsDoNotExposeSecretsOrRepeat(t *testing.T) {
	clock := time.Now()
	host := &readinessHost{}
	a := &authenticator{cfg: Config{MaxStale: 5 * time.Minute}, now: func() time.Time { return clock }, host: host,
		state: state{secret: "fixture-ingest-token-must-not-be-reported", fetched: clock}}
	a.reportReadiness()
	a.reportReadiness()
	clock = clock.Add(5 * time.Minute)
	a.reportReadiness()
	a.reportReadiness()
	a.state.fetched = clock
	a.reportReadiness()
	a.stopped = true
	a.reportReadiness()
	want := []componentstatus.Status{componentstatus.StatusOK, componentstatus.StatusRecoverableError, componentstatus.StatusOK, componentstatus.StatusRecoverableError}
	if len(host.events) != len(want) {
		t.Fatal("readiness transitions were repeated or missing")
	}
	for i, event := range host.events {
		if event.Status() != want[i] {
			t.Fatal("incorrect readiness transition")
		}
		if event.Err() != nil && event.Err().Error() != "openbaoauth: credentials unavailable" {
			t.Fatal("unbounded readiness error")
		}
	}
}

func TestLifecycleMetricsBackoffExpiryRecoveryAndRevoke(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	clock := time.Now()
	a := &authenticator{cfg: f.cfg, now: func() time.Time { return clock }}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())
	if err := a.registerMetrics(provider); err != nil {
		t.Fatal(err)
	}
	collect := func() map[string]float64 {
		var result metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &result); err != nil {
			t.Fatal(err)
		}
		values := map[string]float64{}
		for _, scope := range result.ScopeMetrics {
			for _, m := range scope.Metrics {
				switch data := m.Data.(type) {
				case metricdata.Gauge[int64]:
					for _, p := range data.DataPoints {
						values[m.Name] = float64(p.Value)
					}
				case metricdata.Gauge[float64]:
					for _, p := range data.DataPoints {
						values[m.Name] = p.Value
					}
				case metricdata.Sum[int64]:
					for _, p := range data.DataPoints {
						values[m.Name] = float64(p.Value)
					}
				}
			}
		}
		if text := fmt.Sprint(result); strings.Contains(text, "fixture-bao-session") || strings.Contains(text, "fixture-ingest-token") {
			t.Fatal("secret in telemetry")
		}
		return values
	}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := collect(); got["openbao_ready"] != 1 || got["openbao_last_success_timestamp_seconds"] != float64(clock.Unix()) {
		t.Fatal(got)
	}
	a.mu.RLock()
	renewAt := a.state.session.renewAt
	a.mu.RUnlock()
	if renewAt.Sub(clock) != 40*time.Minute {
		t.Fatal("renewal is not at two-thirds TTL")
	}
	f.mu.Lock()
	f.deny = true
	f.mu.Unlock()
	if err := a.refresh(context.Background()); err == nil {
		t.Fatal("outage accepted")
	}
	if a.triggerAuthRefresh() || a.delay() < 5*time.Second || a.delay() > 10*time.Second {
		t.Fatal("auth signal bypasses backoff")
	}
	clock = clock.Add(6 * time.Minute)
	if got := collect(); got["openbao_ready"] != 0 || got["openbao_snapshot_age_seconds"] != 360 || got["openbao_refresh_failures"] != 1 || got["openbao_consecutive_failures"] != 1 {
		t.Fatal(got)
	}
	f.mu.Lock()
	f.deny = false
	f.generation = 2
	f.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := collect(); got["openbao_ready"] != 1 || got["openbao_consecutive_failures"] != 0 || got["openbao_refresh_failures"] != 1 || got["openbao_rotations"] != 1 {
		t.Fatal(got)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	revokes := f.revokes
	f.mu.Unlock()
	if revokes != 1 || a.state.secret != "" || a.triggerAuthRefresh() {
		t.Fatal("shutdown did not revoke and clear once")
	}
	for failures := int64(1); failures < 100; failures++ {
		delay := retryDelay(failures)
		if delay < 5*time.Second || delay > 5*time.Minute {
			t.Fatal(delay)
		}
	}
}

type rejectingTransport struct{ calls atomic.Int64 }

func (r *rejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied"))}, nil
}

func TestConsumer403RefreshDebounceAndNoReplay(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown(context.Background())
	f.mu.Lock()
	f.generation = 2
	f.mu.Unlock()
	upstream := &rejectingTransport{}
	transport, _ := a.RoundTripper(upstream)
	req, _ := http.NewRequest("POST", f.cfg.ExportEndpoint+"/v1/logs", strings.NewReader("synthetic"))
	for i := 0; i < 20; i++ {
		response, err := transport.RoundTrip(req)
		if err != nil || response.StatusCode != 403 {
			t.Fatal("original denial was not preserved")
		}
		response.Body.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		a.mu.RLock()
		version, triggers := a.state.version, a.lifecycle.AuthRefreshes
		a.mu.RUnlock()
		if triggers != 1 {
			t.Fatal("refresh signal was not debounced")
		}
		if version == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("consumer refresh did not reach snapshot")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstream.calls.Load() != 20 || req.Header.Get("Authorization") != "" {
		t.Fatal("request replayed or mutated")
	}
}

func TestShutdownRevokeHasFiveSecondBound(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.slowRevoke = true
	f.mu.Unlock()
	started := time.Now()
	if err := a.Shutdown(context.Background()); err != errUnavailable {
		t.Fatal("hanging revoke was not reported")
	}
	if time.Since(started) > 6*time.Second || a.state.secret != "" || a.state.session.token != "" {
		t.Fatal("shutdown was not bounded or cleared")
	}
}

func TestRevokeUsesCachedSessionWithoutBootstrapFiles(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Model an old login transport that cannot trust the current server anymore.
	a.mu.Lock()
	a.state.session.client = &http.Client{}
	a.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	logins := f.logins
	f.mu.Unlock()
	if logins != 1 {
		t.Fatal("transport update unnecessarily reauthenticated")
	}
	for _, path := range []string{f.cfg.CAFile, f.cfg.CertFile, f.cfg.KeyFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	revokes := f.revokes
	f.mu.Unlock()
	if revokes != 1 {
		t.Fatal("session was not revoked")
	}
}
