// Command thresholdd exposes all six luxfi/threshold protocols
// (cggmp21, frost, pulsar, corona, bls, doerner) over a single
// process-local JSON-RPC 2.0 endpoint.
//
// Wire format mirrors the teleport mpc bus (mpc/src/signers/rpc.ts):
//
//	POST / with body
//	  {"jsonrpc":"2.0","id":N,"method":"<scheme>.<op>","params":{...}}
//
// Methods (six namespaces, three ops each):
//
//	<scheme>.keygen { threshold, participants }
//	                -> { publicKey: hex, shares: [hex, ...] }
//	<scheme>.sign   { messageHex, pubKeyHex }
//	                -> { signatureHex }
//	<scheme>.verify { messageHex, signatureHex, pubKeyHex }
//	                -> { ok: bool }
//
// The dispatcher itself lives in pkg/thresholdd so the same server is
// embedded by luxfi/mpc's production daemon (mpcd): one wire, one
// implementation, two startup paths.
//
// Bind defaults to 127.0.0.1:7300 — this is process-local IPC.
// Use --listen :0 to take a random port for parallel tests.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7300", "bind address for JSON-RPC server")
	flag.Parse()

	srv, err := thresholdd.NewServer()
	if err != nil {
		log.Fatalf("thresholdd: build server: %v", err)
	}

	// Optional bearer-token auth (Red HIGH B1). Empty token = no gate;
	// matches the historical dev-tooling default but lets operators
	// flip it on without touching the binary.
	if tok := os.Getenv("THRESHOLDD_AUTH_TOKEN"); tok != "" {
		srv.SetAuthToken(tok)
		fmt.Fprintln(os.Stderr, "thresholdd: bearer-token auth enabled")
	}

	// Refuse non-loopback binds unless explicitly overridden. Closes
	// the operator-typo attack: a stray `--listen 0.0.0.0:7300` would
	// otherwise expose the dispatcher cluster-wide. Override knob is
	// THRESHOLDD_ALLOW_REMOTE=1 (mirrors the MPC_THRESHOLD_ALLOW_REMOTE
	// knob in luxfi/mpc's mpcd).
	if !isLoopbackBind(*listen) && os.Getenv("THRESHOLDD_ALLOW_REMOTE") != "1" {
		log.Fatalf(
			"thresholdd: refusing non-loopback bind %q without "+
				"THRESHOLDD_ALLOW_REMOTE=1 (use 127.0.0.1:* / [::1]:* or set the env)",
			*listen,
		)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("thresholdd: listen %s: %v", *listen, err)
	}

	httpSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "thresholdd: listening on %s\n", ln.Addr())

	idle := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		close(idle)
	}()

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("thresholdd: serve: %v", err)
	}
	<-idle
}

// isLoopbackBind reports whether the given listen address resolves to
// a loopback or unspecified-but-explicit-loopback host. Accepts the
// historical `:port` shorthand only when paired with `127.0.0.1` /
// `[::1]`; bare `:7300` (which resolves to 0.0.0.0:7300) is NOT
// considered loopback — operators must spell out the host.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// Bare `:port` binds to all interfaces → not loopback.
		return false
	}
	if host == "localhost" {
		return true
	}
	if strings.EqualFold(host, "::1") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
