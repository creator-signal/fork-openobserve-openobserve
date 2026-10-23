package openbaoauthextension

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	mu                               sync.Mutex
	generation                       int
	deny, broad, oversized, redirect bool
	logins, reads, certs             int
	cfg                              Config
	server                           *httptest.Server
}

func makeFixture(t *testing.T, endpoint string) *fixture {
	t.Helper()
	directory := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	makePair := func(serial int64, client bool) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "collector-fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if client {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
	}
	serverCert, serverKey := makePair(2, false)
	clientCert, clientKey := makePair(3, true)
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	f := &fixture{generation: 1}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("certificate authentication absent")
			w.WriteHeader(403)
			return
		}
		f.certs++
		if f.deny {
			w.WriteHeader(403)
			io.WriteString(w, "do-not-log-upstream-secret")
			return
		}
		if f.redirect {
			w.Header().Set("Location", "https://unexpected.invalid/secret")
			w.WriteHeader(302)
			return
		}
		if r.URL.Path == "/v1/auth/cert/login" || r.URL.Path == "/v1/auth/token/renew-self" {
			if r.Method != http.MethodPost {
				w.WriteHeader(405)
				return
			}
			if r.URL.Path == "/v1/auth/cert/login" {
				var login map[string]string
				if json.NewDecoder(r.Body).Decode(&login) != nil || login["name"] != "fixture-collector" {
					w.WriteHeader(403)
					return
				}
			} else if r.Header.Get("X-Vault-Token") != "fixture-bao-session" {
				w.WriteHeader(403)
				return
			}
			f.logins++
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "fixture-bao-session", "lease_duration": 3600, "renewable": true}})
			return
		}
		if r.Header.Get("X-Vault-Token") != "fixture-bao-session" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path != "/v1/kv/data/observability/collector" {
			t.Error("unexpected record scope")
			w.WriteHeader(404)
			return
		}
		f.reads++
		if f.oversized {
			io.WriteString(w, strings.Repeat("x", maxBody+1))
			return
		}
		fields := map[string]string{"schema": "creator-signal.openobserve-collector/v1", "automation_ingest_token": fmt.Sprintf("fixture-ingest-token-%032d", f.generation)}
		if f.broad {
			fields["root_password"] = "must-not-accept-broad-record"
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": fields}})
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.server = server
	f.cfg = Config{Address: server.URL, Role: "fixture-collector", CAFile: filepath.Join(directory, "ca.pem"), CertFile: filepath.Join(directory, "client.pem"), KeyFile: filepath.Join(directory, "key.pem"), RecordPath: "kv/data/observability/collector", ExportEndpoint: endpoint, RefreshInterval: time.Minute, MaxStale: 5 * time.Minute}
	for filename, content := range map[string][]byte{f.cfg.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), f.cfg.CertFile: clientCert, f.cfg.KeyFile: clientKey} {
		if err := os.WriteFile(filename, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func request(t *testing.T, a *authenticator, transport http.RoundTripper, endpoint string) error {
	t.Helper()
	rt, err := a.RoundTripper(transport)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", endpoint+"/v1/logs", strings.NewReader("synthetic-otlp"))
	response, err := rt.RoundTrip(req)
	if response != nil {
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("export was rejected")
		}
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("credential mutated caller-owned request")
	}
	return err
}

func TestWrongCertificateRoleCannotReadRecord(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	f.cfg.Role = "wrong-role"
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.Start(context.Background(), nil); err == nil {
		t.Fatal("wrong certificate role admitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reads != 0 || a.state.secret != "" {
		t.Fatal("wrong certificate role acquired a record")
	}
}
func TestCertificateAuthRotationAndRestrictedExporter(t *testing.T) {
	var mu sync.Mutex
	generation := 1
	received := 0
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		user, password, ok := r.BasicAuth()
		if !ok || user != username || password != fmt.Sprintf("fixture-ingest-token-%032d", generation) {
			t.Error("scoped exporter credential mismatch")
			w.WriteHeader(403)
			return
		}
		received++
	}))
	defer receiver.Close()
	endpoint := receiver.URL + "/api/default"
	f := makeFixture(t, endpoint)
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown(context.Background())
	if err := request(t, a, receiver.Client().Transport, endpoint); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.generation = 2
	f.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	generation = 2
	mu.Unlock()
	if err := request(t, a, receiver.Client().Transport, endpoint); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", a, a), "fixture-ingest") {
		t.Fatal("debug output disclosed credential")
	}
	f.mu.Lock()
	if f.logins != 1 || f.reads != 2 || f.certs < 3 {
		t.Error("session reuse or certificate verification was not exercised")
	}
	f.mu.Unlock()
	mu.Lock()
	if received != 2 {
		t.Error("export path was not exercised")
	}
	mu.Unlock()
	files, _ := os.ReadDir(filepath.Dir(f.cfg.KeyFile))
	if len(files) != 3 {
		t.Fatal("runtime credential file was written")
	}
	rt, _ := a.RoundTripper(receiver.Client().Transport)
	for _, suffix := range []string{"/api/default/v1/admin", "/api/other/v1/logs", "/api/default/v1/logs?token=bad"} {
		req, _ := http.NewRequest("POST", receiver.URL+suffix, nil)
		if _, err := rt.RoundTrip(req); err != errDestination {
			t.Fatal("exporter path escaped its scope")
		}
	}
	other, _ := http.NewRequest("POST", "https://unexpected.invalid/api/default/v1/logs", nil)
	if _, err := rt.RoundTrip(other); err != errDestination {
		t.Fatal("credential could reach another origin")
	}
}
func TestOutageExpiryColdStartAndRecovery(t *testing.T) {
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer receiver.Close()
	endpoint := receiver.URL + "/api/default"
	f := makeFixture(t, endpoint)
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.deny = true
	f.mu.Unlock()
	err := a.refresh(context.Background())
	if err == nil || strings.Contains(err.Error(), "do-not-log-upstream-secret") {
		t.Fatal("denial was not redacted")
	}
	if err := request(t, a, receiver.Client().Transport, endpoint); err != nil {
		t.Fatal("bounded last-good snapshot was unavailable")
	}
	a.mu.Lock()
	a.state.fetched = time.Now().Add(-6 * time.Minute)
	a.mu.Unlock()
	if err := request(t, a, receiver.Client().Transport, endpoint); err != errUnavailable {
		t.Fatal("expired snapshot remained usable")
	}
	cold := &authenticator{cfg: f.cfg, now: time.Now}
	if err := cold.Start(context.Background(), nil); err == nil {
		cold.Shutdown(context.Background())
		t.Fatal("cold start succeeded without Bao")
	}
	f.mu.Lock()
	f.deny = false
	f.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := request(t, a, receiver.Client().Transport, endpoint); err != nil {
		t.Fatal("recovery failed")
	}
}
func TestBroadOversizedAndRedirectedRecordsAreDenied(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	initial := a.state.secret
	a.mu.RUnlock()
	for _, mode := range []string{"broad", "oversized", "redirect"} {
		f.mu.Lock()
		f.broad = mode == "broad"
		f.oversized = mode == "oversized"
		f.redirect = mode == "redirect"
		f.mu.Unlock()
		if err := a.refresh(context.Background()); err == nil {
			t.Fatal("invalid record accepted")
		}
		a.mu.RLock()
		unchanged := a.state.secret == initial
		a.mu.RUnlock()
		if !unchanged {
			t.Fatal("invalid record replaced last-good state")
		}
	}
}
func TestRenewalRevokedSessionAndCertificateReload(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	a := &authenticator{cfg: f.cfg, now: time.Now}
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.session.expires = time.Now().Add(time.Second)
	a.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.session.token = "revoked-fixture-session"
	a.mu.Unlock()
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.logins != 3 {
		t.Error("renewal and denied-session reauthentication absent")
	}
	f.mu.Unlock()
	key, _ := os.ReadFile(f.cfg.KeyFile)
	os.WriteFile(f.cfg.KeyFile, []byte("invalid-fixture-key"), 0600)
	if err := a.refresh(context.Background()); err != errConfig {
		t.Fatal("changed invalid certificate key was ignored")
	}
	os.WriteFile(f.cfg.KeyFile, key, 0600)
	if err := a.refresh(context.Background()); err != nil {
		t.Fatal("certificate recovery failed")
	}
}
func TestConfigurationRejectsUnsafeOriginsAndScopes(t *testing.T) {
	f := makeFixture(t, "https://observe.example.test/api/default")
	for _, address := range []string{"http://bao.example.test", "https://user:secret@bao.example.test", "https://bao.example.test/path", "https://bao.example.test?token=secret"} {
		cfg := f.cfg
		cfg.Address = address
		if cfg.Validate() == nil {
			t.Fatal("unsafe address accepted")
		}
	}
	for _, path := range []string{"kv/data/runtime", "kv/data/../collector", "kv/data/%2e%2e/collector", "/kv/data/collector"} {
		cfg := f.cfg
		cfg.RecordPath = path
		if cfg.Validate() == nil {
			t.Fatal("unsafe record accepted")
		}
	}
}
