package test

import (
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Network is the in-memory message bus used by every protocol test.
//
// Close discipline: Send takes inFlight.RLock for the duration of the
// publish; Close takes inFlight.Lock so all in-flight publishes drain
// before closing the underlying channels. This is the only way to make
// "go network.Send(msg)" + deferred network.Close() race-free without
// either widening Send's lock (which would serialize the harness) or
// dropping messages.
type Network struct {
	messages map[party.ID]chan *protocol.Message
	done     map[party.ID]chan struct{}
	mu       sync.RWMutex

	inFlight sync.RWMutex
	closed   bool
}

// NewNetwork creates an in-memory test network with buffered per-party queues.
func NewNetwork(parties []party.ID) *Network {
	n := &Network{
		messages: make(map[party.ID]chan *protocol.Message),
		done:     make(map[party.ID]chan struct{}),
	}

	for _, id := range parties {
		n.messages[id] = make(chan *protocol.Message, 1000)
		n.done[id] = make(chan struct{})
	}

	return n
}

// Send routes a message to the appropriate party.
//
// Holds inFlight.RLock for the duration of the publish so Close (which
// takes inFlight.Lock) waits for every in-flight send to complete before
// closing the channels. If Close already ran, Send returns immediately
// without panicking.
func (n *Network) Send(msg *protocol.Message) {
	if msg == nil {
		return
	}

	n.inFlight.RLock()
	defer n.inFlight.RUnlock()
	if n.closed {
		return
	}

	n.mu.RLock()
	targets := make([]chan *protocol.Message, 0)

	if msg.To == "" {
		// Broadcast to all parties except sender
		for id, ch := range n.messages {
			if id != msg.From {
				targets = append(targets, ch)
			}
		}
	} else {
		// Send to specific party
		if ch, ok := n.messages[msg.To]; ok {
			targets = append(targets, ch)
		}
	}
	n.mu.RUnlock()

	// Send without holding n.mu (lock-order: inFlight.RLock is still held).
	for _, ch := range targets {
		ch <- msg
	}
}

// Next returns the message channel for a party
func (n *Network) Next(id party.ID) <-chan *protocol.Message {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if ch, ok := n.messages[id]; ok {
		return ch
	}
	return nil
}

// Done returns the done channel for a party
func (n *Network) Done(id party.ID) <-chan struct{} {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if ch, ok := n.done[id]; ok {
		return ch
	}
	return nil
}

// SetSession is a no-op for the in-memory network.
func (n *Network) SetSession([]byte) {}

// Close closes all channels.
//
// Blocks until every in-flight Send has returned, so callers may safely
// defer Close from the test goroutine even when fire-and-forget
// "go network.Send(msg)" calls are still running in HandlerLoop.
func (n *Network) Close() {
	// Acquire write lock — waits for every Send (held with RLock) to drain
	// and prevents new ones from entering the publish path.
	n.inFlight.Lock()
	defer n.inFlight.Unlock()
	if n.closed {
		return
	}
	n.closed = true

	n.mu.Lock()
	defer n.mu.Unlock()

	for _, ch := range n.done {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
	}

	for _, ch := range n.messages {
		close(ch)
	}
}
