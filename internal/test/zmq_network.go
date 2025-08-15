package test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	zmq "github.com/luxfi/zmq/v4"
)

// ZMQNetwork provides message passing for protocol testing using luxfi/zmq/v4
type ZMQNetwork struct {
	mu          sync.RWMutex
	parties     []party.ID
	publisher   zmq.Socket
	subscribers map[party.ID]zmq.Socket
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewZMQNetwork creates a test network using luxfi/zmq/v4
func NewZMQNetwork(parties []party.ID) (*ZMQNetwork, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create publisher socket
	publisher := zmq.NewPub(ctx)

	// Use a fixed port for testing
	pubAddr := "tcp://127.0.0.1:15000"
	err := publisher.Listen(pubAddr)
	if err != nil {
		// Try another port if busy
		pubAddr = "tcp://127.0.0.1:15001"
		err = publisher.Listen(pubAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to bind publisher: %w", err)
		}
	}

	n := &ZMQNetwork{
		parties:     parties,
		publisher:   publisher,
		subscribers: make(map[party.ID]zmq.Socket),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Create subscribers for each party
	for _, id := range parties {
		subscriber := zmq.NewSub(ctx)

		// Connect to publisher
		err = subscriber.Dial(pubAddr)
		if err != nil {
			n.Close()
			return nil, fmt.Errorf("failed to connect subscriber for %s: %w", id, err)
		}

		// Subscribe to messages for this party (and broadcasts)
		err = subscriber.SetOption(zmq.OptionSubscribe, string(id))
		if err != nil {
			n.Close()
			return nil, fmt.Errorf("failed to subscribe for %s: %w", id, err)
		}
		err = subscriber.SetOption(zmq.OptionSubscribe, "BROADCAST")
		if err != nil {
			n.Close()
			return nil, fmt.Errorf("failed to subscribe to broadcast for %s: %w", id, err)
		}

		n.subscribers[id] = subscriber
	}

	// Allow time for connections to establish
	time.Sleep(100 * time.Millisecond)

	return n, nil
}

// Send broadcasts a message through ZeroMQ
func (n *ZMQNetwork) Send(msg *protocol.Message) {
	if msg == nil {
		return
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	// Determine routing
	var topic string
	if msg.To == "" {
		topic = "BROADCAST"
	} else {
		topic = string(msg.To)
	}

	// Create ZMQ message with topic and data
	zmqMsg := zmq.NewMsgFromString([]string{topic, string(data)})

	// Send through ZeroMQ
	err = n.publisher.Send(zmqMsg)
	if err != nil {
		// Log error silently
		return
	}
}

// Next returns a channel for receiving messages for a party
func (n *ZMQNetwork) Next(id party.ID) <-chan *protocol.Message {
	ch := make(chan *protocol.Message, 100)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer close(ch)

		n.mu.RLock()
		subscriber, ok := n.subscribers[id]
		n.mu.RUnlock()

		if !ok {
			return
		}

		for {
			select {
			case <-n.ctx.Done():
				return
			default:
			}

			// Receive message with non-blocking check
			zmqMsg, err := subscriber.Recv()
			if err != nil {
				// Timeout or error, continue
				continue
			}

			// Check we have at least 2 frames (topic and data)
			if len(zmqMsg.Frames) < 2 {
				continue
			}

			topic := string(zmqMsg.Frames[0])
			data := zmqMsg.Frames[1]

			// Skip if not for us
			if topic != string(id) && topic != "BROADCAST" {
				continue
			}

			// Deserialize message
			var msg protocol.Message
			err = json.Unmarshal(data, &msg)
			if err != nil {
				continue
			}

			// Send to channel
			select {
			case ch <- &msg:
			case <-n.ctx.Done():
				return
			}
		}
	}()

	return ch
}

// Close shuts down the network
func (n *ZMQNetwork) Close() {
	n.cancel()
	n.wg.Wait()

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.publisher != nil {
		n.publisher.Close()
	}

	for _, subscriber := range n.subscribers {
		if subscriber != nil {
			subscriber.Close()
		}
	}
}
