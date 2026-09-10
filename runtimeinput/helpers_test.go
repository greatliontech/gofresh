package runtimeinput

import (
	"context"
	"os"
)

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entries name both.
func ambientFromTestLog(log []byte, moduleDir, packageDir string, opts ...TestLogOption) (Observation, error) {
	return FromTestLog(log, moduleDir, packageDir, os.Environ(), opts...)
}

func ambientIncomplete(moduleDir, process, reason string) (Observation, error) {
	return Incomplete(moduleDir, process, reason, os.Environ())
}

func ambientAbsolute(observation Observation, moduleDir string) (Observation, error) {
	return Absolute(observation, moduleDir, os.Environ())
}

func ambientRelative(observation Observation, moduleDir string) (Observation, error) {
	return Relative(observation, moduleDir, os.Environ())
}

func ambientDirty(observation Observation, moduleDir, commit string, inspector CommitInspector) (bool, error) {
	return Dirty(observation, moduleDir, commit, inspector, os.Environ())
}

func ambientMerge(moduleDir string, observations ...Observation) (Observation, error) {
	return Merge(moduleDir, os.Environ(), observations...)
}

func ambientCurrent(encoded, moduleDir string) (State, error) {
	return Current(context.Background(), encoded, moduleDir, os.Environ())
}

func ambientCurrentEnv(encoded, moduleDir string, env []string) (State, error) {
	return Current(context.Background(), encoded, moduleDir, env)
}

func ambientMovedInputs(encoded, moduleDir string, env []string) ([]string, error) {
	return MovedInputs(context.Background(), encoded, moduleDir, env)
}

func ambientCaptureBracket(moduleDir string, roots []string, opts ...BracketOption) (Bracket, error) {
	return CaptureBracket(context.Background(), moduleDir, roots, opts...)
}
