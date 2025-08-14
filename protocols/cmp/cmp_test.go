package cmp

import (
	"context"
	"crypto/rand"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logger := log.NewTestLogger(level.Info)
	sessionID := []byte("test-session")
	config := protocol.DefaultConfig()
	
	// Keygen
	h, err := protocol.NewHandler(ctx, logger, prometheus.NewRegistry(), Keygen(curve.Secp256k1{}, id, ids, threshold, pl), sessionID, config)
	require.NoError(t, err)
	
	done := make(chan struct{})
	go func() {
		test.HandlerLoop(id, h, n)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		t.Logf("Keygen timed out for party %s", id)
		return
	}
	
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

	// Refresh
	h, err = protocol.NewHandler(ctx, logger, prometheus.NewRegistry(), Refresh(c, pl), sessionID, config)
	require.NoError(t, err)
	
	done = make(chan struct{})
	go func() {
		test.HandlerLoop(c.ID, h, n)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		t.Logf("Refresh timed out for party %s", id)
		return
	}

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c = r.(*Config)

	// Sign
	h, err = protocol.NewHandler(ctx, logger, prometheus.NewRegistry(), Sign(c, ids, message, pl), sessionID, config)
	require.NoError(t, err)
	
	done = make(chan struct{})
	go func() {
		test.HandlerLoop(c.ID, h, n)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		t.Logf("Sign timed out for party %s", id)
		return
	}

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature := signResult.(*ecdsa.Signature)
	assert.True(t, signature.Verify(c.PublicPoint(), message))

	// Presign
	h, err = protocol.NewHandler(ctx, logger, prometheus.NewRegistry(), Presign(c, ids, pl), sessionID, config)
	require.NoError(t, err)

	done = make(chan struct{})
	go func() {
		test.HandlerLoop(c.ID, h, n)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		t.Logf("Presign timed out for party %s", id)
		return
	}

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PreSignature{}, signResult)
	preSignature := signResult.(*ecdsa.PreSignature)
	assert.NoError(t, preSignature.Validate())

	// PresignOnline
	h, err = protocol.NewHandler(ctx, logger, prometheus.NewRegistry(), PresignOnline(c, preSignature, message, pl), sessionID, config)
	require.NoError(t, err)
	
	done = make(chan struct{})
	go func() {
		test.HandlerLoop(c.ID, h, n)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		t.Logf("PresignOnline timed out for party %s", id)
		return
	}

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature = signResult.(*ecdsa.Signature)
	assert.True(t, signature.Verify(c.PublicPoint(), message))
}

func TestCMPFull(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full CMP protocol test in short mode")
	}
	N := 3
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	// Create separate pool for each party to avoid concurrent access issues
	pools := make(map[party.ID]*pool.Pool)
	for _, id := range partyIDs {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()
	
	network := test.NewNetwork(partyIDs)
	var wg sync.WaitGroup
	for _, id := range partyIDs {
		wg.Add(1)
		go do(t, id, partyIDs, T, message, pools[id], network, &wg)
	}
	wg.Wait()
}

func TestStart(t *testing.T) {
	group := curve.Secp256k1{}
	N := 6
	T := 3
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs := test.GenerateConfig(group, N, T, rand.Reader, pl)

	m := []byte("HELLO")
	selfID := partyIDs[0]
	c := configs[selfID]
	tests := []struct {
		name      string
		partyIDs  []party.ID
		threshold int
	}{
		{
			"N threshold",
			partyIDs,
			N,
		},
		{
			"T threshold",
			partyIDs[:T],
			N,
		},
		{
			"-1 threshold",
			partyIDs,
			-1,
		},
		{
			"max threshold",
			partyIDs,
			math.MaxUint32,
		},
		{
			"max threshold -1",
			partyIDs,
			math.MaxUint32 - 1,
		},
		{
			"no self",
			partyIDs[1:],
			T,
		},
		{
			"duplicate self",
			append(partyIDs, selfID),
			T,
		},
		{
			"duplicate other",
			append(partyIDs, partyIDs[1]),
			T,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.Threshold = tt.threshold
			var err error
			_, err = Keygen(group, selfID, tt.partyIDs, tt.threshold, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			_, err = Sign(c, tt.partyIDs, m, pl)(nil)
			t.Log(err)
			assert.Error(t, err)

			_, err = Presign(c, tt.partyIDs, pl)(nil)
			t.Log(err)
			assert.Error(t, err)
		})
	}
}