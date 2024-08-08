package reputationfuzz

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

// FuzzLadderAttack tests for scenarios where a fuzzing attack is economical
// for an attacker, setting up various network patterns from the fuzzer's input.
func FuzzLadderAttack(f *testing.F) {
	f.Add(
		uint64(120_000), uint64(20_667), uint64(300), uint8(4),
		[]byte{100, 10, 25, 50},
	)

	f.Fuzz(func(t *testing.T, firstNodeTraffic, attackerPayment uint64,
		cltvTotal uint64, networkLength uint8, networkDescription []byte) {

		// We need to have at least 3 nodes in our network to run a
		// meaningful test, and the current network diameter is 10 so
		// we don't bother with more than that.
		if networkLength < 3 || networkLength > 10 {
			return
		}

		// Restrict hold time to protocol maximum.
		if cltvTotal > 2016 {
			return
		}

		// We need at least one byte per node in the network to
		// determine its traffic flow.
		if len(networkDescription) < int(networkLength) {
			return
		}

		cfg := ladderingAttackCfg{
			firstNodeTraffic: firstNodeTraffic,
			trafficFlows:     make([]trafficFlow, networkLength),
		}

		for i := 0; i < int(networkLength); i++ {
			// Make sure we have a value that's sane for a
			// percentage.
			portion := networkDescription[i]
			if portion == 0 || portion > 100 {
				return
			}

			cfg.trafficFlows[i] = trafficFlow{
				trafficPortion: portion,
			}
		}

		ladder, err := newLadderingAttack(cfg)
		if err != nil {
			return
		}

		// We want the revenue threshold for nodes along the ladder to
		// be increasing, otherwise we're not actually testing a ladder
		// of nodes (connecting to a big node to attack a small node is
		// not a cost saving.
		var preRevenue uint64
		for _, channel := range ladder.channels {
			if channel.outgoingRevenue < preRevenue {
				return
			}

			preRevenue = channel.outgoingRevenue
		}

		// We need to have a cltv that's big enough for our route.
		finalCltv, err := ladder.finalCLTV(cltvTotal)
		if err != nil {
			return
		}

		// Check that the target node can get at least 1000 msat
		// endorsed with their peer, otherwise they're not a very
		// interesting node to target.
		channelCount := len(ladder.channels)
		targetReputation := ladder.channels[channelCount-2].incomingReputation
		peerThreshold := ladder.channels[channelCount-1].outgoingRevenue
		minimumHTLC := htlcReputationCost(1000, finalCltv)

		if targetReputation < peerThreshold+minimumHTLC {
			return
		}

		totalEndorsed, err := ladder.totalEndorsedOnTarget(
			attackerPayment, cltvTotal,
		)
		if errors.Is(err, errInsufficientCltv) {
			return
		}

		outcome := ladder.attackOutcome(totalEndorsed, cltvTotal)
		if outcome.effective(attackerPayment) {
			t.Errorf("Successful laddering attack: %v\n%v\n with "+
				"first node: %v, attacker payment: %v, %v "+
				"endorsed (height: %v) with outcome: %v", ladder,
				cfg.trafficFlows, firstNodeTraffic,
				attackerPayment, totalEndorsed, cltvTotal,
				outcome)
		}
	})
}

// FuzzSurgeAttack tests for scenarios where inflating the value of an outgoing
// link so that honest peers lose reputation and then general jamming is a
// successful strategy.
func FuzzSurgeAttack(f *testing.F) {
	// ChatGPT.
	honestPeers := []byte{
		0xD0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20000
		0x90, 0xB6, 0x59, 0x3B, 0x00, 0x00, 0x00, 0x00, // 1000000000
		0x1F, 0x4E, 0x44, 0x0A, 0x00, 0x00, 0x00, 0x00, // 172145567
		0x2E, 0x11, 0x1A, 0x0B, 0x00, 0x00, 0x00, 0x00, // 184831534
		0x5F, 0xA6, 0x38, 0x07, 0x00, 0x00, 0x00, 0x00, // 123435487
		0x7A, 0xC3, 0x5B, 0x2F, 0x00, 0x00, 0x00, 0x00, // 796435450
		0x4B, 0x20, 0x1C, 0x1A, 0x00, 0x00, 0x00, 0x00, // 437569355
		0x1E, 0xAB, 0x33, 0x16, 0x00, 0x00, 0x00, 0x00, // 372389150
		0x55, 0xF6, 0x48, 0x12, 0x00, 0x00, 0x00, 0x00, // 306875861
		0x8C, 0xDA, 0x2C, 0x10, 0x00, 0x00, 0x00, 0x00, // 271043852
	}
	f.Add(uint8(10), honestPeers)

	f.Fuzz(func(t *testing.T, peerCount uint8, peerTraffic []byte) {
		// Attacks are only interesting with 2+ nodes.
		if peerCount < 2 {
			return
		}

		cutoff := int(rand.Intn(int(peerCount)))

		// Cutoff must be a valid index in the peer count slice.
		if cutoff >= int(peerCount) {
			return
		}

		// We need traffic flows expressed as uint64 for each node.
		if len(peerTraffic) < int(peerCount)*8 {
			return
		}

		honestPeers := make([]uint64, peerCount)
		for i := 0; i < int(peerCount); i++ {
			fees := binary.LittleEndian.Uint64(peerTraffic[i*8 : (i+1)*8])
			if fees == 0 {
				return
			}

			// Cut off fee around 1 btc in msat, reasonable ballpark.
			if fees > 1_000_000_00_000 {
				return
			}
			honestPeers[i] = fees
		}

		outcome, err := surgeAttack(
			honestPeers, int(cutoff),
		)
		if err != nil {
			return
		}

		if success, err := outcome.success(); success || err != nil {
			t.Errorf("Successful attack against: %v with cutoff: %v\n"+
				"Outcome: %v: %v", honestPeers, cutoff, outcome, err)
		}
	})
}
