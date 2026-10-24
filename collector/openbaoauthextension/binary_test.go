package openbaoauthextension

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// CI builds the actual distribution first. Unit-only invocations retain an
// explicit skip, never a substitute claim of running-collector acceptance.
func TestDistributionIngestionRotationRestartAndNoSecretFiles(t *testing.T) {
	binary := os.Getenv("OPENBAO_COLLECTOR_BINARY")
	if binary == "" {
		t.Skip("OPENBAO_COLLECTOR_BINARY is required for distribution acceptance")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("collector binary must be an absolute owned build path")
	}
	var mu sync.Mutex
	accepted := map[string]int{}
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, token, ok := r.BasicAuth()
		if !ok || user != username || r.URL.Path != "/api/default/v1/logs" {
			w.WriteHeader(403)
			return
		}
		mu.Lock()
		accepted[token]++
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer receiver.Close()
	f := makeFixture(t, receiver.URL+"/api/default")
	f.cfg.RefreshInterval = 5 * time.Second
	directory := filepath.Dir(f.cfg.KeyFile)
	receiverCA := filepath.Join(directory, "exporter-ca.pem")
	cert, err := x509.ParseCertificate(receiver.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	input := listener.Addr().String()
	listener.Close()
	healthListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := healthListener.Addr().String()
	_, healthPort, _ := net.SplitHostPort(healthAddress)
	healthListener.Close()
	probe := filepath.Join(t.TempDir(), "collector-healthcheck")
	if output, err := exec.Command("go", "build", "-o", probe, "./cmd/healthcheck").CombinedOutput(); err != nil {
		t.Fatalf("readiness probe build failed: %v (%d output bytes)", err, len(output))
	}
	health := func(wantReady bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			output, err := exec.Command(probe, "--port="+healthPort).CombinedOutput()
			if len(output) != 0 {
				t.Fatal("readiness probe produced output")
			}
			if (err == nil) == wantReady {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
		t.Fatal("collector readiness did not reach expected state")
	}
	config := fmt.Sprintf(`extensions:
  health_check:
    http:
      endpoint: %q
      status:
        enabled: true
        path: /
    component_health:
      include_recoverable_errors: true
      include_permanent_errors: true
      recovery_duration: 0s
  openbaoauth:
    address: %q
    cert_role: fixture-collector
    ca_file: %q
    cert_file: %q
    key_file: %q
    record_path: kv/data/observability/collector
    export_endpoint: %q
    refresh_interval: 5s
    max_stale: 10s
receivers:
  otlp:
    protocols:
      http:
        endpoint: %q
exporters:
  otlp_http:
    endpoint: %q
    tls:
      ca_file: %q
    auth:
      authenticator: openbaoauth
service:
  extensions: [health_check, openbaoauth]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlp_http]
`, healthAddress, f.cfg.Address, f.cfg.CAFile, f.cfg.CertFile, f.cfg.KeyFile, f.cfg.ExportEndpoint, input, f.cfg.ExportEndpoint, receiverCA)
	filename := filepath.Join(directory, "collector.yaml")
	if err := os.WriteFile(filename, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	run := func() (func(), *bytes.Buffer) {
		command := exec.Command(binary, "--feature-gates=+extension.healthcheck.useComponentStatus", "--config="+filename)
		var output bytes.Buffer
		command.Stdout = &output
		command.Stderr = &output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		stop := func() { once.Do(func() { command.Process.Kill(); command.Wait() }) }
		t.Cleanup(stop)
		return stop, &output
	}
	emit := func(generation int) {
		t.Helper()
		expected := fmt.Sprintf("fixture-ingest-token-%032d", generation)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"1","body":{"stringValue":"synthetic-fixture-signal"}}]}]}]}`
			request, _ := http.NewRequest("POST", "http://"+input+"/v1/logs", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			client := http.Client{Timeout: time.Second}
			response, err := client.Do(request)
			if err == nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			mu.Lock()
			count := accepted[expected]
			mu.Unlock()
			if count > 0 {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
		t.Fatal("collector did not deliver the expected credential generation")
	}
	stop, output := run()
	emit(1)
	health(true)
	f.mu.Lock()
	f.generation = 2
	f.mu.Unlock()
	emit(2)
	f.mu.Lock()
	f.deny = true
	f.mu.Unlock()
	// Exercise the actual distribution and image probe after freshness expires.
	time.Sleep(11 * time.Second)
	health(false)
	f.mu.Lock()
	f.deny = false
	f.mu.Unlock()
	health(true)
	emit(2)
	stop()
	if strings.Contains(output.String(), "fixture-ingest-token") || strings.Contains(output.String(), "fixture-bao-session") || strings.Contains(output.String(), "do-not-log-upstream-secret") {
		t.Fatal("collector logged a credential")
	}
	mu.Lock()
	accepted = map[string]int{}
	mu.Unlock()
	stop, output = run()
	emit(2)
	stop()
	if strings.Contains(output.String(), "fixture-ingest-token") {
		t.Fatal("restart logged a credential")
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatal("unexpected runtime credential or cache file")
	}
	for _, file := range files {
		if strings.Contains(file.Name(), "token") || strings.Contains(file.Name(), "secret") {
			t.Fatal("secret projection exists")
		}
	}
}
