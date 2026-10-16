//go:build race

package state

// raceEnabled is set when the race detector, which slows everything down
// several times over, is on.
const raceEnabled = true
