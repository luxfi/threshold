package frost_test

import (
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FROST Protocol", func() {
	var (
		partyIDs []party.ID
		message  []byte
	)

	BeforeEach(func() {
		message = []byte("test message for FROST protocol")
	})

	runParty := func(partyIDs []party.ID, threshold int, message []byte) {
		// Phase 1: Keygen
		harness1 := test.NewHarness(nil, partyIDs)
		defer harness1.Cleanup()
		sessionID1 := []byte("test-keygen")
		
		for _, id := range partyIDs {
			startFunc := frost.Keygen(curve.Secp256k1{}, id, partyIDs, threshold)
			_, err := harness1.CreateHandler(id, startFunc, sessionID1)
			Expect(err).NotTo(HaveOccurred())
		}
		
		err := harness1.Run()
		Expect(err).NotTo(HaveOccurred())
		
		results1 := harness1.Results()
		configs := make(map[party.ID]*frost.Config)
		for id, r := range results1 {
			Expect(r).To(BeAssignableToTypeOf(&frost.Config{}))
			configs[id] = r.(*frost.Config)
		}
		
		// Phase 2: Refresh
		harness2 := test.NewHarness(nil, partyIDs)
		defer harness2.Cleanup()
		sessionID2 := []byte("test-refresh")
		
		for id, config := range configs {
			startFunc := frost.Refresh(config, partyIDs)
			_, err := harness2.CreateHandler(id, startFunc, sessionID2)
			Expect(err).NotTo(HaveOccurred())
		}
		
		err = harness2.Run()
		Expect(err).NotTo(HaveOccurred())
		
		results2 := harness2.Results()
		refreshedConfigs := make(map[party.ID]*frost.Config)
		for id, r := range results2 {
			Expect(r).To(BeAssignableToTypeOf(&frost.Config{}))
			refreshedConfigs[id] = r.(*frost.Config)
			Expect(configs[id].PublicKey.Equal(refreshedConfigs[id].PublicKey)).To(BeTrue())
		}
		
		// Phase 3: Sign
		harness3 := test.NewHarness(nil, partyIDs)
		defer harness3.Cleanup()
		sessionID3 := []byte("test-sign")
		
		for id, config := range refreshedConfigs {
			startFunc := frost.Sign(config, partyIDs, message)
			_, err := harness3.CreateHandler(id, startFunc, sessionID3)
			Expect(err).NotTo(HaveOccurred())
		}
		
		err = harness3.Run()
		Expect(err).NotTo(HaveOccurred())
		
		results3 := harness3.Results()
		for id, r := range results3 {
			Expect(r).To(BeAssignableToTypeOf(&frost.Signature{}))
			signature := r.(*frost.Signature)
			Expect(signature.Verify(refreshedConfigs[id].PublicKey, message)).To(BeTrue())
		}
	}

	Context("with 2-out-of-3 threshold", func() {
		BeforeEach(func() {
			partyIDs = test.PartyIDs(3)
		})

		It("should complete full protocol flow", func() {
			runParty(partyIDs, 2, message)
		})
	})

	Context("with 3-out-of-5 threshold", func() {
		BeforeEach(func() {
			partyIDs = test.PartyIDs(5)
		})

		It("should complete full protocol flow", func() {
			runParty(partyIDs, 3, message)
		})
	})

	Context("with 5-out-of-7 threshold", func() {
		BeforeEach(func() {
			partyIDs = test.PartyIDs(7)
		})

		It("should complete full protocol flow", func() {
			runParty(partyIDs, 5, message)
		})
	})

})