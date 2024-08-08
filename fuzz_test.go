package ladderattack

import (
	"errors"
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
