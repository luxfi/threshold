// Package protocol provides context utilities for threshold signature protocols
package protocol

import (
	"context"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// Context is just an alias for standard context.Context for cleaner call sites
type Context = context.Context

// SessionInfo holds immutable protocol session information
type SessionInfo struct {
	SessionID []byte
	SelfID    party.ID
	PartyIDs  []party.ID
	Threshold int
	Group     curve.Curve
	Protocol  string // "cmp", "frost", "lss", etc.
}

// Private key type to avoid collisions
type sessionKey struct{}

var sessionK sessionKey

// WithSession sets session info in context (call once at protocol start)
func WithSession(ctx context.Context, info SessionInfo) context.Context {
	return context.WithValue(ctx, sessionK, info)
}

// sessionFrom retrieves session info from context
func sessionFrom(ctx context.Context) (SessionInfo, bool) {
	v, ok := ctx.Value(sessionK).(SessionInfo)
	return v, ok
}

// MustSession panics if session info is missing (fail-fast pattern)
func MustSession(ctx context.Context) SessionInfo {
	v, ok := sessionFrom(ctx)
	if !ok {
		panic("protocol: SessionInfo missing from context")
	}
	return v
}

// Minimal accessor functions for least typing at call sites

// SessionID returns the session identifier
func SessionID(ctx context.Context) []byte {
	return MustSession(ctx).SessionID
}

// Self returns the local party ID
func Self(ctx context.Context) party.ID {
	return MustSession(ctx).SelfID
}

// Parties returns all party IDs
func Parties(ctx context.Context) []party.ID {
	return MustSession(ctx).PartyIDs
}

// Threshold returns the threshold value
func Threshold(ctx context.Context) int {
	return MustSession(ctx).Threshold
}

// Group returns the curve group
func Group(ctx context.Context) curve.Curve {
	return MustSession(ctx).Group
}

// Protocol returns the protocol name
func Protocol(ctx context.Context) string {
	return MustSession(ctx).Protocol
}

// LogFields returns structured logging fields from context
func LogFields(ctx context.Context) []interface{} {
	info := MustSession(ctx)
	return []interface{}{
		"protocol", info.Protocol,
		"session", info.SessionID,
		"self", info.SelfID,
		"threshold", info.Threshold,
		"parties", len(info.PartyIDs),
	}
}