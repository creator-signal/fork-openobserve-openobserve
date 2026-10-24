package main

import (
	"flag"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Only a numeric port is configurable. Proxy configuration, redirects,
// credentials and response bodies never enter this loopback readiness check.
func run(args []string) int {
	flags := flag.NewFlagSet("collector-healthcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	port := flags.Int("port", 13133, "loopback readiness port")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *port < 1 || *port > 65535 {
		return 1
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(*port) + "/")
	if err != nil {
		return 1
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:])) }
