package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
)

// StartFunc is function that creates the first round of a protocol.
// It returns the first round initialized with the session information.
// If the creation fails (likely due to misconfiguration), and error is returned.
//
// An optional sessionID can be provided, which should unique among all protocol executions.
type StartFunc func(sessionID []byte) (round.Session, error)

// Handler represents some kind of handler for a protocol.
type Handler interface {
	// Result should return the result of running the protocol, or an error
	Result() (interface{}, error)
	// Listen returns a channel which will receive new messages
	Listen() <-chan *Message
	// Stop should abort the protocol execution.
	Stop()
	// CanAccept checks whether or not a message can be accepted at the current point in the protocol.
	CanAccept(msg *Message) bool
	// Accept advances the protocol execution after receiving a message.
	Accept(msg *Message)
}

// MultiHandler represents an execution of a given protocol.
// It provides a simple interface for the user to receive/deliver protocol messages.
type MultiHandler struct {
	currentRound    round.Session
	rounds          map[round.Number]round.Session
	err             *Error
	result          interface{}
	messages        map[round.Number]map[party.ID]*Message
	broadcast       map[round.Number]map[party.ID]*Message
	broadcastHashes map[round.Number][]byte
	out             chan *Message
	mtx             sync.Mutex
}

// NewMultiHandler expects a StartFunc for the desired protocol. It returns a handler that the user can interact with.
func NewMultiHandler(create StartFunc, sessionID []byte) (*MultiHandler, error) {
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	h := &MultiHandler{
		currentRound:    r,
		rounds:          map[round.Number]round.Session{r.Number(): r},
		messages:        make(map[round.Number]map[party.ID]*Message),
		broadcast:       make(map[round.Number]map[party.ID]*Message),
		broadcastHashes: map[round.Number][]byte{},
		out:             make(chan *Message, 2*r.N()),
	}
	// Initialize storage for the first round
	h.initRoundStorage(r)
	h.finalizeInitial()
	return h, nil
}

// Result returns the protocol result if the protocol completed successfully. Otherwise an error is returned.
func (h *MultiHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.result != nil {
		return h.result, nil
	}
	if h.err != nil {
		return nil, *h.err
	}
	return nil, errors.New("protocol: not finished")
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// The message received should be _reliably_ broadcast if msg.Broadcast is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *MultiHandler) Listen() <-chan *Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.out
}

// CanAccept returns true if the message is designated for this protocol protocol execution.
func (h *MultiHandler) CanAccept(msg *Message) bool {
	r := h.currentRound
	if msg == nil {
		return false
	}
	// are we the intended recipient
	if !msg.IsFor(r.SelfID()) {
		return false
	}
	// is the protocol ID correct
	if msg.Protocol != r.ProtocolID() {
		return false
	}
	// check for same SSID
	if !bytes.Equal(msg.SSID, r.SSID()) {
		return false
	}
	// do we know the sender
	if !r.PartyIDs().Contains(msg.From) {
		return false
	}

	// data is cannot be nil
	if msg.Data == nil {
		return false
	}

	// check if message for unexpected round
	if msg.RoundNumber > r.FinalRoundNumber() {
		return false
	}

	// Check if message is for a round we've already passed
	// msg.RoundNumber < r.Number() means the message is for an earlier round
	// We reject it unless it's round 0 (abort message)
	if msg.RoundNumber < r.Number() && msg.RoundNumber > 0 {
		// This is the condition that's likely failing
		// If we're in round 2 and receive a round 1 message, we reject it
		return false
	}

	return true
}

// Accept tries to process the given message. If an abort occurs, the channel returned by Listen() is closed,
// and an error is returned by Result().
//
// This function may be called concurrently from different threads but may block until all previous calls have finished.
func (h *MultiHandler) Accept(msg *Message) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// exit early if the message is bad, or if we are already done
	if !h.CanAccept(msg) || h.err != nil || h.result != nil || h.duplicate(msg) {
		return
	}

	// a msg with roundNumber 0 is considered an abort from another party
	if msg.RoundNumber == 0 {
		h.abort(fmt.Errorf("aborted by other party with error: \"%s\"", msg.Data), msg.From)
		return
	}

	h.store(msg)
	if h.currentRound.Number() != msg.RoundNumber {
		return
	}

	if msg.Broadcast {
		if err := h.verifyBroadcastMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	} else {
		if err := h.verifyMessage(msg); err != nil {
			h.abort(err, msg.From)
			return
		}
	}

	h.finalize()
}

func (h *MultiHandler) verifyBroadcastMessage(msg *Message) error {
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}

	// try to convert the raw message into a round.Message
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// store the broadcast message for this round
	if err = r.(round.BroadcastRound).StoreBroadcastMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	// if the round only expected a broadcast message, we can safely return
	if !expectsNormalMessage(r) {
		return nil
	}

	// otherwise, we can try to handle the p2p message that may be stored.
	msg = h.messages[msg.RoundNumber][msg.From]
	if msg == nil {
		return nil
	}

	return h.verifyMessage(msg)
}

// verifyMessage tries to handle a normal (non reliably broadcast) message for this current round.
func (h *MultiHandler) verifyMessage(msg *Message) error {
	// we simply return if we haven't reached the right round.
	r, ok := h.rounds[msg.RoundNumber]
	if !ok {
		return nil
	}

	// exit if we don't yet have the broadcast message
	if _, ok = r.(round.BroadcastRound); ok {
		q := h.broadcast[msg.RoundNumber]
		if q == nil || q[msg.From] == nil {
			return nil
		}
	}

	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		return err
	}

	// verify message for round
	if err = r.VerifyMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

// finalizeInitial is called during handler initialization to generate initial messages
// without advancing the round
func (h *MultiHandler) finalizeInitial() {
	// For round 1 broadcast rounds, generate the initial broadcast but don't advance yet
	if h.currentRound.Number() != 1 {
		return
	}
	
	if _, ok := h.currentRound.(round.BroadcastRound); !ok {
		return
	}
	
	// Special handling: generate broadcast but stay in round 1
	out := make(chan *round.Message, h.currentRound.N()+1)
	r, err := h.currentRound.Finalize(out)
	close(out)
	
	if err != nil {
		h.abort(err, h.currentRound.SelfID())
		return
	}
	
	// Save the next round for later but don't advance to it yet
	if r != nil && r.Number() > h.currentRound.Number() {
		h.rounds[r.Number()] = r
		// Pre-initialize storage for round 2 so it's ready when we advance
		h.initRoundStorage(r)
	}
	
	// Forward messages
	for roundMsg := range out {
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		msg := &Message{
			SSID:                  h.currentRound.SSID(),
			From:                  h.currentRound.SelfID(),
			To:                    roundMsg.To,
			Protocol:              h.currentRound.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast,
			BroadcastVerification: nil,
		}
		if msg.Broadcast {
			// Store our own broadcast for hash calculation
			h.store(msg)
			// Verify it was stored
			if h.broadcast[msg.RoundNumber] != nil && h.broadcast[msg.RoundNumber][msg.From] == nil {
				// Storage failed - this is a problem
				// For debugging: try to understand why
			}
		}
		h.out <- msg
	}
	// Stay in round 1 to accept other broadcasts
}

func (h *MultiHandler) finalize() {
	// Special case: Round 2 needs to send shares immediately without waiting
	if h.currentRound.Number() == 2 && expectsNormalMessage(h.currentRound) {
		// Check if we've already sent shares (to avoid double-sending)
		// If round 3 exists, we've already sent shares
		if _, ok := h.rounds[3]; !ok {
			// fmt.Printf("Handler %s: Round 2 - sending shares immediately\n", h.currentRound.SelfID())
			// Call Finalize to generate and send share messages
			out2 := make(chan *round.Message, h.currentRound.N()+1)
			nextRound, err := h.currentRound.Finalize(out2)
			close(out2)
			
			if err != nil {
				h.abort(err, h.currentRound.SelfID())
				return
			}
			
			// Send the share messages
			for roundMsg := range out2 {
				data, err := cbor.Marshal(roundMsg.Content)
				if err != nil {
					panic(fmt.Errorf("failed to marshal round message: %w", err))
				}
				msg := &Message{
					SSID:                  h.currentRound.SSID(),
					From:                  h.currentRound.SelfID(),
					To:                    roundMsg.To,
					Protocol:              h.currentRound.ProtocolID(),
					RoundNumber:           roundMsg.Content.RoundNumber(),
					Data:                  data,
					Broadcast:             roundMsg.Broadcast,
					BroadcastVerification: h.broadcastHashes[h.currentRound.Number()-1],
				}
				h.out <- msg
			}
			
			// Save and advance to round 3
			if nextRound != nil {
				h.rounds[nextRound.Number()] = nextRound
				// Don't advance yet - we'll do that when we receive all shares
			}
			// Return here to avoid sending shares again in the normal flow
			return
		}
	}
	
	// only finalize if we have received all messages
	if !h.receivedAll() {
		// fmt.Printf("finalize: Not all messages received for round %d (handler %s)\n", h.currentRound.Number(), h.currentRound.SelfID())
		return
	}
	// fmt.Printf("finalize: All messages received for round %d (handler %s), advancing...\n", h.currentRound.Number(), h.currentRound.SelfID())
	if !h.checkBroadcastHash() {
		h.abort(errors.New("broadcast verification failed"))
		return
	}

	// Check if we've already finalized this round 
	nextRoundNumber := h.currentRound.Number() + 1
	if existingRound, ok := h.rounds[nextRoundNumber]; ok {
		// We've already finalized this round, just advance to the next
		h.currentRound = existingRound
		// Initialize storage for the next round
		h.initRoundStorage(existingRound)
		
		// Process any queued messages for the new round
		h.processQueuedMessages()
		return
	}

	out := make(chan *round.Message, h.currentRound.N()+1)
	// since we pass a large enough channel, we should never get an error
	r, err := h.currentRound.Finalize(out)
	close(out)
	// either we got an error due to some problem on our end (sampling etc)
	// or the new round is nil (should not happen)
	if err != nil || r == nil {
		h.abort(err, h.currentRound.SelfID())
		return
	}

	// forward messages with the correct header.
	for roundMsg := range out {
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		msg := &Message{
			SSID:                  r.SSID(),
			From:                  r.SelfID(),
			To:                    roundMsg.To,
			Protocol:              r.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast,
			BroadcastVerification: h.broadcastHashes[r.Number()-1],
		}
		if msg.Broadcast {
			h.store(msg)
		}
		h.out <- msg
	}

	roundNumber := r.Number()
	// if we get a round with the same number, we can safely assume that we got the same one.
	if _, ok := h.rounds[roundNumber]; ok {
		return
	}
	h.rounds[roundNumber] = r
	h.currentRound = r
	// fmt.Printf("Handler %s: Advanced to round %d\n", r.SelfID(), r.Number())
	// Initialize storage for the new round
	h.initRoundStorage(r)

	// either we get the current round, the next one, or one of the two final ones
	switch R := r.(type) {
	// An abort happened
	case *round.Abort:
		h.abort(R.Err, R.Culprits...)
		return
	// We have the result
	case *round.Output:
		h.result = R.Result
		h.abort(nil)
		return
	default:
	}

	if _, ok := r.(round.BroadcastRound); ok {
		// handle queued broadcast messages, which will then check the subsequent normal message
		for id, m := range h.broadcast[roundNumber] {
			if m == nil || id == r.SelfID() {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyBroadcastMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	} else {
		// handle simple queued messages
		for _, m := range h.messages[roundNumber] {
			if m == nil {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	}

	// we only do this if the current round has changed
	h.finalize()
}

func (h *MultiHandler) processQueuedMessages() {
	roundNumber := h.currentRound.Number()
	
	if _, ok := h.currentRound.(round.BroadcastRound); ok {
		// handle queued broadcast messages
		for id, m := range h.broadcast[roundNumber] {
			if m == nil || id == h.currentRound.SelfID() {
				continue
			}
			// if false, we aborted and so we return
			if err := h.verifyBroadcastMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	} else {
		// handle simple queued messages
		for _, m := range h.messages[roundNumber] {
			if m == nil {
				continue
			}
			// if false, we aborted and so we return
			if err := h.verifyMessage(m); err != nil {
				h.abort(err, m.From)
				return
			}
		}
	}
	
	// Continue processing if needed
	h.finalize()
}

func (h *MultiHandler) abort(err error, culprits ...party.ID) {
	if err != nil {
		h.err = &Error{
			Culprits: culprits,
			Err:      err,
		}
		select {
		case h.out <- &Message{
			SSID:     h.currentRound.SSID(),
			From:     h.currentRound.SelfID(),
			Protocol: h.currentRound.ProtocolID(),
			Data:     []byte(h.err.Error()),
		}:
		default:
		}

	}
	close(h.out)
}

// Stop cancels the current execution of the protocol, and alerts the other users.
func (h *MultiHandler) Stop() {
	if h.err != nil || h.result != nil {
		h.abort(errors.New("aborted by user"), h.currentRound.SelfID())
	}
}

func expectsNormalMessage(r round.Session) bool {
	return r.MessageContent() != nil
}

func (h *MultiHandler) receivedAll() bool {
	r := h.currentRound
	number := r.Number()
	// check all broadcast messages
	if _, ok := r.(round.BroadcastRound); ok {
		// fmt.Printf("receivedAll: Round %d IS a BroadcastRound\n", number)
		// Only check broadcasts if this round actually broadcasts
		if h.broadcast[number] == nil {
			// No broadcast storage means we haven't initialized it yet
			// This should not happen if initRoundStorage was called
			return false
		}
		
		// Normal case: check for all broadcasts
		// We need all broadcasts including our own for the hash
		for _, id := range r.PartyIDs() {
			msg := h.broadcast[number][id]
			if msg == nil {
				// Debug: Print which party's broadcast is missing
				if id == r.SelfID() {
					// Our own broadcast is missing - this shouldn't happen
					// fmt.Printf("WARNING: Handler %s missing OWN broadcast for round %d\n", r.SelfID(), number)
				}
				// fmt.Printf("Handler %s missing broadcast from %s for round %d\n", r.SelfID(), id, number)
				return false
			}
		}

		// create hash of all message for this round
		if h.broadcastHashes[number] == nil {
			hashState := r.Hash()
			for _, id := range r.PartyIDs() {
				msg := h.broadcast[number][id]
				_ = hashState.WriteAny(&hash.BytesWithDomain{
					TheDomain: "Message",
					Bytes:     msg.Hash(),
				})
			}
			h.broadcastHashes[number] = hashState.Sum()
		}
	}

	// check all normal messages
	if expectsNormalMessage(r) {
		if h.messages[number] == nil {
			// No message storage means no messages expected
			return true
		}
		for _, id := range r.OtherPartyIDs() {
			if h.messages[number][id] == nil {
				return false
			}
		}
	}
	return true
}

func (h *MultiHandler) duplicate(msg *Message) bool {
	if msg.RoundNumber == 0 {
		return false
	}
	var q map[party.ID]*Message
	if msg.Broadcast {
		q = h.broadcast[msg.RoundNumber]
	} else {
		q = h.messages[msg.RoundNumber]
	}
	// technically, we already received the nil message since it is not expected :)
	if q == nil {
		return true
	}
	return q[msg.From] != nil
}

func (h *MultiHandler) store(msg *Message) {
	var q map[party.ID]*Message
	if msg.Broadcast {
		q = h.broadcast[msg.RoundNumber]
	} else {
		q = h.messages[msg.RoundNumber]
	}
	if q == nil {
		// Storage not initialized for this round
		// fmt.Printf("store: Storage not initialized for round %d (broadcast=%v)\n", msg.RoundNumber, msg.Broadcast)
		return
	}
	if q[msg.From] != nil {
		// Already have a message from this sender
		// fmt.Printf("store: Already have message from %s for round %d\n", msg.From, msg.RoundNumber)
		return
	}
	q[msg.From] = msg
	// fmt.Printf("store: Stored message from %s for round %d (broadcast=%v)\n", msg.From, msg.RoundNumber, msg.Broadcast)
}

// getRoundMessage attempts to unmarshal a raw Message for round `r` in a round.Message.
// If an error is returned, we should abort.
func getRoundMessage(msg *Message, r round.Session) (round.Message, error) {
	var content round.Content

	// there are two possible content messages
	if msg.Broadcast {
		b, ok := r.(round.BroadcastRound)
		if !ok {
			return round.Message{}, errors.New("got broadcast message when none was expected")
		}
		content = b.BroadcastContent()
	} else {
		content = r.MessageContent()
	}

	// unmarshal message
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

// checkBroadcastHash is run after receivedAll() and checks whether all provided verification hashes are correct.
func (h *MultiHandler) checkBroadcastHash() bool {
	number := h.currentRound.Number()
	// check BroadcastVerification
	previousHash := h.broadcastHashes[number-1]
	if previousHash == nil {
		return true
	}

	for _, msg := range h.messages[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	for _, msg := range h.broadcast[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			return false
		}
	}
	return true
}

func newQueue(senders []party.ID, rounds round.Number) map[round.Number]map[party.ID]*Message {
	n := len(senders)
	q := make(map[round.Number]map[party.ID]*Message, rounds)
	// Start from round 1 to support protocols that broadcast in the first round
	for i := round.Number(1); i <= rounds; i++ {
		q[i] = make(map[party.ID]*Message, n)
		for _, id := range senders {
			q[i][id] = nil
		}
	}
	return q
}

func (h *MultiHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.currentRound.SelfID(), h.currentRound.ProtocolID())
}

// initRoundStorage initializes message storage for a specific round based on its requirements
func (h *MultiHandler) initRoundStorage(r round.Session) {
	number := r.Number()
	
	// Initialize broadcast storage only if this is a broadcast round
	if _, ok := r.(round.BroadcastRound); ok {
		if h.broadcast[number] == nil {
			h.broadcast[number] = make(map[party.ID]*Message, r.N())
			for _, id := range r.PartyIDs() {
				h.broadcast[number][id] = nil
			}
		}
	}
	
	// Initialize message storage only if this round expects messages
	if expectsNormalMessage(r) {
		if h.messages[number] == nil {
			h.messages[number] = make(map[party.ID]*Message, r.N()-1)
			for _, id := range r.OtherPartyIDs() {
				h.messages[number][id] = nil
			}
		}
	}
}
