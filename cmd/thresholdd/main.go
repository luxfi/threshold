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
