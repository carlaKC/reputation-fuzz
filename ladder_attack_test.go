package ladderattack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLadderAttackSetup tests setup against manually generated values.
func TestLadderAttackSetup(t *testing.T) {
	cfg := ladderingAttackCfg{
		firstNodeTraffic: 120_000,
		trafficFlows: []trafficFlow{
			{
				trafficPortion: 100,
			},
			{
				trafficPortion: 10,
			},
			{
				trafficPortion: 25,
			},
			{
				trafficPortion: 50,
			},
		},
	}

	attack, err := newLadderingAttack(cfg)
	require.NoError(t, err)
	require.Len(t, attack.channels, 4)

	assert.EqualValues(t, attack.channels[0].outgoingRevenue, 10_000)
	assert.EqualValues(t, attack.channels[0].incomingReputation, 120_000)

	assert.EqualValues(t, attack.channels[1].outgoingRevenue, 100_000)
	assert.EqualValues(t, attack.channels[1].incomingReputation, 1_200_000)

	assert.EqualValues(t, attack.channels[2].outgoingRevenue, 400_000)
	assert.EqualValues(t, attack.channels[2].incomingReputation, 4_800_000)

	assert.EqualValues(t, attack.channels[3].outgoingRevenue, 800_000)
	assert.EqualValues(t, attack.channels[3].incomingReputation, 9_600_000)

	var attackAmt uint64 = 20_667
	endorsedTotal := attack.totalEndorsedOnTarget(attackAmt, 160)
	require.EqualValues(t, 10, endorsedTotal)

	require.False(t, attack.attackEffective(attackAmt, endorsedTotal, 160))
}
