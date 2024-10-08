# Reputation Fuzzing

Fuzz tests to explore attacks against reputation.

Note that generally we require that a node can get at least $1 of HTLCs endorsed for them to be considered to have sufficiently interesting reputation to attack.

## Ladder Attack
Fuzzing coverage for a laddering attack against our proposed [reputation algorithm](https://github.com/lightning/bolts/pull/1071).

See [sheet](https://docs.google.com/spreadsheets/d/1AmuRE7-XAZzfy-Ku6MyK1AVfE-aj5j66fb6c5_Zbr7c/edit?gid=0#gid=0) for visual walkthrough.

`go test -v -fuzz=FuzzLadderAttack`

## Surge Attack 
Fuzzing coverage for surge attacks that inflate the value of a node's outgoing link to cut peers reputation off.

`go test -v -fuzz=FuzzSurgeAttack`
