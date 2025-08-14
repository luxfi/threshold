package test

import (
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h *protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				// the channel was closed, indicating that the protocol is done executing.
				// Don't wait on network.Done(id) as it may not be signaled properly
				return
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)
		}
	}
}
