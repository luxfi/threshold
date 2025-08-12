package test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/zmq/v4/networking"
)

// ZMQNetwork provides real network communication for protocol testing using ZMQ4
type ZMQNetwork struct {
	parties    party.IDSlice
	transports map[party.ID]*networking.Transport
	handlers   map[party.ID]chan *protocol.Message
	basePort   int
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
}

// NewZMQNetwork creates a new ZMQ4-based network for protocol testing
func NewZMQNetwork(ctx context.Context, parties party.IDSlice, basePort int) *ZMQNetwork {
	netCtx, cancel := context.WithCancel(ctx)
	return &ZMQNetwork{
		parties:    parties,
		transports: make(map[party.ID]*networking.Transport),
		handlers:   make(map[party.ID]chan *protocol.Message),
		basePort:   basePort,
		ctx:        netCtx,
		cancel:     cancel,
	}
}

// Start initializes all party transports and connects them
func (n *ZMQNetwork) Start() error {
	// Create transport for each party
	for i, id := range n.parties {
		config := networking.Config{
			NodeID:      string(id),
			BasePort:    n.basePort + i*10, // Each party gets unique port range
			BindAddress: "127.0.0.1",
			MaxRetries:  3,
			RetryDelay:  100 * time.Millisecond,
			BufferSize:  1000,
		}

		transport := networking.New(n.ctx, config)
		n.transports[id] = transport

		// Create handler channel
		n.handlers[id] = make(chan *protocol.Message, 100)

		// Start the transport
		if err := transport.Start(); err != nil {
			return fmt.Errorf("failed to start transport for %s: %w", id, err)
		}

		// Register protocol message handler
		transport.RegisterHandler("protocol", n.createHandler(id))
	}

	// Connect all parties to each other
	for _, id1 := range n.parties {
		transport1 := n.transports[id1]
		for j, id2 := range n.parties {
			if id1 != id2 {
				port := n.basePort + j*10
				if err := transport1.ConnectPeer(string(id2), port); err != nil {
					return fmt.Errorf("failed to connect %s to %s: %w", id1, id2, err)
				}
			}
		}
	}

	// Give connections time to establish
	time.Sleep(200 * time.Millisecond)

	return nil
}

// Stop shuts down all transports
func (n *ZMQNetwork) Stop() {
	n.cancel()

	// Stop all transports
	for _, transport := range n.transports {
		transport.Stop()
	}

	// Close all handler channels
	n.mu.Lock()
	for _, ch := range n.handlers {
		close(ch)
	}
	n.mu.Unlock()

	n.wg.Wait()
}

// Next returns the channel for receiving messages for a party
func (n *ZMQNetwork) Next(id party.ID) <-chan *protocol.Message {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if ch, ok := n.handlers[id]; ok {
		return ch
	}

	// Return closed channel if not found
	closed := make(chan *protocol.Message)
	close(closed)
	return closed
}

// Send broadcasts or sends a protocol message
func (n *ZMQNetwork) Send(msg *protocol.Message) {
	transport, ok := n.transports[msg.From]
	if !ok {
		fmt.Printf("No transport for party %s\n", msg.From)
		return
	}

	// Marshal the protocol message
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("Failed to marshal protocol message: %v\n", err)
		return
	}

	// Create network message
	netMsg := &networking.Message{
		Type:      "protocol",
		From:      string(msg.From),
		SessionID: msg.SSID,
		Data:      data,
		Timestamp: time.Now().UnixNano(),
	}

	// Send to appropriate recipients
	if msg.To != "" {
		// Point-to-point message
		netMsg.To = string(msg.To)
		if err := transport.Send(string(msg.To), netMsg); err != nil {
			fmt.Printf("Failed to send message from %s to %s: %v\n", msg.From, msg.To, err)
		}
	} else {
		// Broadcast message
		if err := transport.Broadcast(netMsg); err != nil {
			fmt.Printf("Failed to broadcast from %s: %v\n", msg.From, err)
		}
	}
}

// Done signals that a party is done
func (n *ZMQNetwork) Done(id party.ID) chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ch, ok := n.handlers[id]; ok {
		close(ch)
		delete(n.handlers, id)
	}

	done := make(chan struct{})
	if len(n.handlers) == 0 {
		close(done)
	}
	return done
}

// createHandler creates a message handler for a specific party
func (n *ZMQNetwork) createHandler(partyID party.ID) networking.MessageHandler {
	return func(msg *networking.Message) {
		// Unmarshal protocol message
		var protocolMsg protocol.Message
		if err := json.Unmarshal(msg.Data, &protocolMsg); err != nil {
			fmt.Printf("Failed to unmarshal protocol message: %v\n", err)
			return
		}

		// Route to party's channel
		n.mu.RLock()
		ch, ok := n.handlers[partyID]
		n.mu.RUnlock()

		if ok && protocolMsg.IsFor(partyID) {
			select {
			case ch <- &protocolMsg:
			default:
				fmt.Printf("Dropped message for %s (channel full)\n", partyID)
			}
		}
	}
}

// GetMetrics returns network metrics for debugging
func (n *ZMQNetwork) GetMetrics() map[party.ID]struct {
	Sent     uint64
	Received uint64
	Dropped  uint64
} {
	metrics := make(map[party.ID]struct {
		Sent     uint64
		Received uint64
		Dropped  uint64
	})

	for id, transport := range n.transports {
		sent, received, dropped := transport.GetMetrics()
		metrics[id] = struct {
			Sent     uint64
			Received uint64
			Dropped  uint64
		}{
			Sent:     sent,
			Received: received,
			Dropped:  dropped,
		}
	}

	return metrics
}
