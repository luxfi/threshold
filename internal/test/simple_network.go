package test

import (
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Network is a local in-memory network for testing (default implementation)
type Network struct {
	messages map[party.ID]chan *protocol.Message
	done     map[party.ID]chan struct{}
	mu       sync.RWMutex
}

// NewNetwork creates a simple test network
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

// Send routes a message to the appropriate party
func (n *Network) Send(msg *protocol.Message) {
	if msg == nil {
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

	// Send without holding lock to avoid deadlock
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

// SetSession is a no-op for simple network
func (n *Network) SetSession([]byte) {}

// Close closes all channels
func (n *Network) Close() {
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
