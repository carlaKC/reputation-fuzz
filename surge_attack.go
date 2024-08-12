package reputationfuzz

import (
	"fmt"
	"sort"
)

// minimumHTLCReputation is the minimum size of HTLC that we require a peer to
// be able to get endorsed for it to have sufficient reputation for us to care
// about the results that we get from fuzzing, expressed in msat. This
// represents around $1 at the time of writing.
const minimumHTLCReputation = 17_00_000

type surgeAttackOutcome struct {
	cutoffReputation uint64
	peaceRevenue     uint64
	attackRevenue    uint64
}

func (s *surgeAttackOutcome) String() string {
	paid := s.cutoffReputation - s.peaceRevenue
	loss := (s.peaceRevenue - (paid + s.attackRevenue)) * 100 / s.peaceRevenue

	return fmt.Sprintf("Node lost: %v %% of revenue  - attacker paid: %v to meet threshold: %v, "+
		"node still earned: %v (%v honest + %v attacker)", loss,
		paid, s.peaceRevenue, s.attackRevenue+paid, s.attackRevenue, paid)
}

func (s *surgeAttackOutcome) success() (bool, error) {
	// If the reputation that we're cutting off is less than the peace
	// time revenue, the peers never had good reputation to start with
	// so there's no point in attacking.
	//
	// Height is hardcoded to a low value here because it isn't really
	// all that relevant to the attack.
	htlcEndorsed := htlcReputationCost(minimumHTLCReputation, 100)

	if s.cutoffReputation < s.peaceRevenue+htlcEndorsed {
		return false, nil
	}

	// The attacker only needs to pay the difference between the best peer
	// it's trying to cut off and the reputation threshold.
	attackerPays := s.cutoffReputation - s.peaceRevenue

	// Since we're always cutting traffic off, we should never have revenue
	// under attack that's more than during peace.
	if s.attackRevenue > s.peaceRevenue {
		return false, fmt.Errorf("attack revenue: %v should be < peace: %v",
			s.attackRevenue, s.peaceRevenue)
	}

	// The attack is only successful if the node earns less than in times
	/// of peace.
	return attackerPays+s.attackRevenue < s.peaceRevenue, nil
}

func revenueFromReputation(reputation uint64) uint64 {
	return reputation * revenuePeriodWeeks / reputationPeriodWeeks
}

// surgeAttack determines whether a targeted node will lose reputation if
// targeted by a reputation surge attack, where an attack inflates the value
// of one of their outgoing links to deny peers reputation to access protected
// slots, then general jams for two weeks.
//
// Honest peers provides the fee revenue from the nodes peers, and cutoff
// provides the index at which the attacker will aim to cut off peer
// reputation (zero value means that the least valuable peer is cut off, because
// there's no point in an attack that doesn't target any peers).
func surgeAttack(honestPeers []uint64, cutoffIndex int) (*surgeAttackOutcome,
	error) {

	if cutoffIndex > len(honestPeers)-1 {
		return nil, fmt.Errorf("Cutoff: %v > peer count: %v",
			cutoffIndex, len(honestPeers))
	}

	// Sort from least to most valuable peer.
	sort.Slice(honestPeers, func(i, j int) bool {
		return honestPeers[i] < honestPeers[j]
	})

	// First, we'll calculate the revenue threshold for the targeted link.
	var (
		twoWeekRevenue     uint64
		attackRevenue      uint64
		reputationToCutOff uint64
	)

	for i, reputation := range honestPeers {
		// We're assuming constant traffic from the node, add it to our
		// two week revenue total (representing when we're not under
		// attack).
		peerContribution := revenueFromReputation(reputation)
		twoWeekRevenue += peerContribution

		// If we're beneath the cutoff, the attacker will need to pay
		// up to this peer's reputation to cut it off from having good
		// reputation.
		//
		// If we're after the cutoff index, this peer will still be able
		// to earn us fees in the two week period that we're attacked.
		if i <= cutoffIndex {
			reputationToCutOff = reputation
		} else {
			attackRevenue += peerContribution
		}
	}

	return &surgeAttackOutcome{
		cutoffReputation: reputationToCutOff,
		peaceRevenue:     twoWeekRevenue,
		attackRevenue:    attackRevenue,
	}, nil
}
