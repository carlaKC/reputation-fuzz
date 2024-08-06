package ladderattack

import "fmt"

const (
	revenuePeriodWeeks = 2

	reputationPeriodWeeks = 24
)

type ladderingAttack struct {
	channels []channel
}

type channel struct {
	incomingReputation uint64
	outgoingRevenue    uint64
}

type ladderingAttackCfg struct {
	// firstNodeTraffic is the amount of payment traffic that is forwarded
	// by the node that the attacker will connect to in an attempt to
	// "ladder" up reputation. Expressed as total volume over a 6 month
	// period.
	//
	// This value is strictly less than the traffic for the node whose
	// reputation the attacker is trying to sabotage, because otherwise it
	// would just make sense to connect directly (rather than perform a
	// laddering attack).
	firstNodeTraffic uint64

        // trafficFlows describes the percentage of total traffic on the link 
        // that is provided by the node that preceeds it. 
        // 
        // For example, if firstNodeTraffic is 100,000 and the first entry is 
        // 50, then the first node in the route has a total of 200,000 in 
        // traffic flowing through it.
        // 
        // The attack will target the penultimate channel in this list for 
        // laddering - eg in A --- B --- C --- D, we're trying to target C's
        // reputation with D.
	trafficFlows []trafficFlow
}

type trafficFlow struct {
	trafficPortion uint8
}

func newLadderingAttack(cfg ladderingAttackCfg) (*ladderingAttack, error) {
	incomingTraffic := cfg.firstNodeTraffic

	if len(cfg.trafficFlows) < 3 {
		return nil, fmt.Errorf("must have at least three channels: %v",
			len(cfg.trafficFlows))
	}

	channels := make([]channel, 0, len(cfg.trafficFlows))

	for _, traffic := range cfg.trafficFlows {
		// Our traffic portion indicates the percentage of our traffic
		// over the outgoing link that the incoming traffic contributes
		// to. We use this value to calculate the total traffic that we
		// have flowing over out outgoing link.
		//
		// This is expressed over a 6 month period, as that's the period
		// that our incoming traffic is expressed over.
		incomingTraffic = incomingTraffic * 100 / uint64(traffic.trafficPortion)

		// The revenue score that we assign our outgoing link is tracked
		// over a 2 week period, so we adjust this period to get our
		// total. Note that this assumes a constant rate of traffic,
		// which allows us to move between time horizons.
		outgoingRevenue := incomingTraffic * revenuePeriodWeeks / reputationPeriodWeeks
		channels = append(channels, channel{
			// TODO: reputation depends on the *next* node's fees.
			incomingReputation: incomingTraffic,
			// TODO: revenue depends on the *current* node's fees.
			outgoingRevenue: outgoingRevenue,
		})
	}

	return &ladderingAttack{
		channels: channels,
	}, nil
}
}
