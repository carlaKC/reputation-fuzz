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

func (l *ladderingAttack) run(attackerPayment uint64) bool {
	// htlcHold is the amount of time that the attacker will try
	// to hold the HTLC on the targeted channel.
	var htlcHold uint64 = 180

	totalEndorsed := l.totalEndorsedOnTarget(attackerPayment, htlcHold)

	return l.attackEffective(attackerPayment, totalEndorsed, htlcHold)
}

// totalEndorsedOnTarget calculates the total amount that an attacker can get
// endorsed on the target node given some payment amount and htlc hold time.
func (l *ladderingAttack) totalEndorsedOnTarget(attackerPayment uint64,
	htlcHold uint64) uint64 {

	var (
		// The reputation total for the attacker is the amount that
		// they have paid.
		// TODO: multiplied by fee policy of smaller node.
		candidateReputation = attackerPayment

		totalEndorsed uint64
	)

	// Based on the amount that the attacker gave us, run through our route
	// to see how large of a HTLC the attacker can get endorsed on the final
	// channel in our path.
	for i := 0; i < len(l.channels)-1; i++ {
		channel := l.channels[i]

		// If the node doesn't even have sufficient reputation to meet
		// the threshold, it won't get any HTLCs endorsed.
		if candidateReputation < channel.outgoingRevenue {
			return 0
		}

		// The amount of reputation that has been built *above* the
		// reputation threshold is the amount that we have available
		// for in-flight HTLCs to be endorsed on this hop.
		currentHopEndorsed := (candidateReputation - channel.outgoingRevenue) * 90 / (htlcHold * 10 * 60)
		if currentHopEndorsed == 0 {
			return 0
		}

		// We can't get *more* endorsed on this hop than the amount
		// that was endorsed on the previous hop, the endorsed amount
		// can only go down. Update our value if we haven't set an
		// endorsed amount yet or we need to decrease our total.
		if totalEndorsed == 0 || currentHopEndorsed < totalEndorsed {
			totalEndorsed = currentHopEndorsed
		}

		// We're now going to use the reputation of the current node
		// to try get endorsed by its peer, so we update our candidate
		// reputation accordingly.
		candidateReputation = channel.incomingReputation
	}

	return totalEndorsed
}

// runAttack takes the amount that an attacker is willing to pay and returns a
// bool indicating whether the attacker is able to sabotage the reputation of
// the target node.
func (l *ladderingAttack) attackEffective(attackerPayment,
	totalEndorsed, htlcHold uint64) bool {

	chanCount := len(l.channels)
	finalNodeRevenue := l.channels[chanCount-1].outgoingRevenue
	targetNode := l.channels[chanCount-2]

	// If the targeted node didn't have good reputation with the last node
	// anyway, then there was no attack to be had to begin with.
	if targetNode.incomingReputation < finalNodeRevenue {
		return false
	}

	// Calculate the total penalty for slowjamming.
	// TODO: totalEndorsed * fee for outgoing node!!
	slowJamCost := htlcReputationCost(totalEndorsed, htlcHold)

	// For our laddering attack to be successful we need two things to be
	// true:
	// 1. The targeted node lost reputation from being slow jammed
	// 2. The attack was actually cheaper than directly attacking the target
	lostReputation := targetNode.incomingReputation < finalNodeRevenue+slowJamCost
	ladderCheaper := targetNode.outgoingRevenue+slowJamCost > attackerPayment

	return lostReputation && ladderCheaper
}

// htlcReputationCost is the cost of getting a htlc endorsed (and the penalty
// for using it to slow jam).
func htlcReputationCost(amount uint64, height uint64) uint64 {
	return (amount * height * 10 * 60) / 90
}
