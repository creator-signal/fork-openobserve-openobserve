package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatusRedirectAndBodyAreBounded(t *testing.T) {
	for _, code := range []int{200, 503, 302} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" || r.Header.Get("Authorization") != "" {
					t.Error("unexpected request")
				}
				w.Header().Set("Location", "/redirect-must-not-be-followed")
				w.WriteHeader(code)
				w.(http.Flusher).Flush()
				// Sending headers is enough; a probe must not wait for a body.
				select {
				case <-r.Context().Done():
				case <-time.After(3 * time.Second):
				}
			}))
			defer server.Close()
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			started := time.Now()
			got := run([]string{"--port=" + port})
			if (got == 0) != (code == 200) || time.Since(started) > time.Second {
				t.Fatal("incorrect or body-dependent health result")
			}
		})
	}
}

func TestTimeoutAndInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"--port=0"}, {"--port=65536"}, {"--port=-1"}, {"--port=abc"}, {"https://example.invalid"}, {"--url=http://example.invalid"}} {
		if run(args) == 0 {
			t.Fatal("invalid arguments accepted")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	started := time.Now()
	if run([]string{"--port=" + port}) == 0 || time.Since(started) > 3*time.Second {
		t.Fatal("timeout was not bounded")
	}
	server.Close()
	if run([]string{"--port=" + port}) == 0 {
		t.Fatal("closed endpoint was healthy")
	}
}
