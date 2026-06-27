// Command thresholdd exposes all luxfi/threshold protocols
// (cggmp21, frost, pulsar, corona, magnetar, doerner) over a
// single process-local ZAP byte-passthrough endpoint.
//
// Wire shape (see ~/work/lux/threshold/pkg/thresholdd/zap_schema.go):
//
//	ZAP message with procedure opcode in msg.Flags upper byte; the
//	procedure name is `<scheme>.<op>` and the dispatcher routes by
//	the FNV-1a opcode derived from that name.
//
// Procedures (per scheme):
//
//	<scheme>.keygen { Threshold, Participants }
//	                -> { PublicKey, Shares }   (all bytes)
//	<scheme>.sign   { Message, PubKey }
//	                -> { Signature }
//	<scheme>.verify { Message, Signature, PubKey }
//	                -> { OK }
//
// The dispatcher itself lives in pkg/thresholdd so the same server is
// embedded by luxfi/mpc's production daemon (mpcd): one wire, one
// implementation, two startup paths.
//
// Bind defaults to 127.0.0.1:7301 — this is process-local IPC.
// Use --listen :0 to take a random port for parallel tests.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7301", "bind address for the ZAP dispatcher")
	flag.Parse()

	// Refuse non-loopback binds unless explicitly overridden. Closes
	// the operator-typo attack: a stray `--listen 0.0.0.0:7301` would
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

	// Split host:port — ZapServerConfig takes an int port. The host
	// half is validated by isLoopbackBind above; the listener inside
	// zap.Node binds 0.0.0.0:<port> + ::0:<port> internally, so a
	// loopback-only deployment relies on the os-level firewall +
	// process-local IPC posture (matches the legacy HTTP path).
	_, portStr, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatalf("thresholdd: bad --listen %q: %v", *listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("thresholdd: bad port %q: %v", portStr, err)
	}

	cfg := thresholdd.ZapServerConfig{
		NodeID:    "thresholdd",
		Port:      port,
		AuthToken: os.Getenv("THRESHOLDD_AUTH_TOKEN"),
	}
	if cfg.AuthToken != "" {
		fmt.Fprintln(os.Stderr, "thresholdd: bearer-token auth enabled")
	}

	srv, err := thresholdd.NewZapServer(cfg)
	if err != nil {
		log.Fatalf("thresholdd: build server: %v", err)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("thresholdd: start: %v", err)
	}
	defer srv.Stop()

	fmt.Fprintf(os.Stderr, "thresholdd: ZAP dispatcher listening on %s (nodeID=%s)\n", *listen, srv.NodeID())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "thresholdd: shutdown signal received")
}

// isLoopbackBind reports whether the given listen address resolves to
// a loopback or unspecified-but-explicit-loopback host. Accepts the
// historical `:port` shorthand only when paired with `127.0.0.1` /
// `[::1]`; bare `:7301` (which resolves to 0.0.0.0:7301) is NOT
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
