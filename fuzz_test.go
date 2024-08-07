package ladderattack

import "testing"

// FuzzLadderAttack tests for scenarios where a fuzzing attack is economical
// for an attacker, setting up various network patterns from the fuzzer's input.
func FuzzLadderAttack(f *testing.F) {
	f.Add(uint64(120_000), uint64(20_667), uint8(4), []byte{100, 10, 25, 50})
	f.Fuzz(func(t *testing.T, firstNodeTraffic, attackerPayment uint64,
		networkLength uint8, networkDescription []byte) {

		// We need to have at least 3 nodes in our network to run a
		// meaningful test, and the current network diameter is 10 so 
                // we don't bother with more than that.
		if networkLength < 3  || networkLength > 10{
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

		var prevPortion uint8
		for i := 0; i < int(networkLength); i++ {
			// Make sure we have a value that's sane for a
			// percentage.
			portion := networkDescription[i]
			if portion == 0 || portion > 100 {
				return
			}

			// By definition, we want traffic along our ladder to
			// increase so that we can take advantage of cheaper
			// nodes at the beginning of the route.
			if portion < prevPortion {
				return
			}

			cfg.trafficFlows[i] = trafficFlow{
				trafficPortion: portion,
			}

			prevPortion = portion
		}

		ladder, err := newLadderingAttack(cfg)
		if err != nil {
			return
		}

		if ladder.run(attackerPayment) {
			t.Errorf("Successful laddering attack: %v\n%v\n with first node: %v, attacker payment: %v", ladder, cfg.trafficFlows, firstNodeTraffic, attackerPayment)
		}
	})
}
