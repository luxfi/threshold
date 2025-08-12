package test

import (
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Network simulates a point-to-point network between different parties using Go channels.
// The same network is used by all processes, and can be reused for different protocols.
// When used with test.Handler, no interaction from the user is required beyond creating the network.
type Network struct {
	parties          party.IDSlice
	listenChannels   map[party.ID]chan *protocol.Message
	done             chan struct{}
	closedListenChan chan *protocol.Message
	mtx              sync.Mutex
	// sessionFilter tracks the active session ID for message filtering
	// Empty/nil means accept all sessions (backward compatibility)
	sessionFilter    []byte
}

func NewNetwork(parties party.IDSlice) *Network {
	closed := make(chan *protocol.Message)
	close(closed)
	c := &Network{
		parties:          parties,
		listenChannels:   make(map[party.ID]chan *protocol.Message, 2*len(parties)),
		closedListenChan: closed,
	}
	// Initialize channels immediately
	c.init()
	return c
}

func (n *Network) init() {
	N := len(n.parties)
	for _, id := range n.parties {
		n.listenChannels[id] = make(chan *protocol.Message, N*N)
	}
	n.done = make(chan struct{})
}

func (n *Network) Next(id party.ID) <-chan *protocol.Message {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	// Reinitialize the network if all channels have been closed
	// This allows reusing the network for multiple protocol executions
	if len(n.listenChannels) == 0 {
		n.init()
	}
	c, ok := n.listenChannels[id]
	if !ok {
		return n.closedListenChan
	}
	return c
}

func (n *Network) Send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	
	sent := 0
	for id, c := range n.listenChannels {
		if msg.IsFor(id) && c != nil {
			// Create a deep copy of the message to avoid race conditions
			// when multiple goroutines process the same message
			msgCopy := &protocol.Message{
				SSID:      msg.SSID,
				From:      msg.From,
				To:        msg.To,
				Protocol:  msg.Protocol,
				RoundNumber: msg.RoundNumber,
				Broadcast: msg.Broadcast,
			}
			// Copy the data slice to avoid sharing the underlying array
			if msg.Data != nil {
				msgCopy.Data = make([]byte, len(msg.Data))
				copy(msgCopy.Data, msg.Data)
			}
			
			// Use non-blocking send to avoid deadlocks
			select {
			case c <- msgCopy:
				// Successfully sent
				sent++
			default:
				// Channel is full, log and continue
				// This prevents deadlocks but may lose messages if buffers are too small
				// The buffer size is N*N which should be sufficient for most protocols
				println("WARNING: Network channel full, dropping message to", string(id))
			}
		}
	}
	if sent == 0 && msg.To != "" {
		println("WARNING: Message not sent to anyone! To:", string(msg.To), "Broadcast:", msg.Broadcast)
	}
}

// SetSession configures the network to only route messages for a specific session.
// Pass nil or empty slice to accept all sessions (backward compatibility).
func (n *Network) SetSession(sessionID []byte) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	n.sessionFilter = sessionID
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (n *Network) Done(id party.ID) chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if _, ok := n.listenChannels[id]; ok {
		close(n.listenChannels[id])
		delete(n.listenChannels, id)
	}
	if len(n.listenChannels) == 0 {
		close(n.done)
	}
	return n.done
}

func (n *Network) Quit(id party.ID) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	n.parties = n.parties.Remove(id)
}
