// Copyright 2021-2023, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE.md

//go:build legacychallengetest
// +build legacychallengetest

package arbtest

import (
	"context"
	"testing"

	"github.com/offchainlabs/nitro/util/testhelpers/github"
)

func TestChallengeManagerFullAsserterIncorrect(t *testing.T) {
	t.Parallel()
	defaultWasmRootDir := ""
	RunChallengeTest(t, false, false, makeBatch_MsgsPerBatch+1, false, false, defaultWasmRootDir)
	RunChallengeTest(t, false, false, makeBatch_MsgsPerBatch+1, true, false, defaultWasmRootDir)
	RunChallengeTest(t, false, false, makeBatch_MsgsPerBatch+1, true, true, defaultWasmRootDir)
}

func TestChallengeManagerFullAsserterIncorrectWithPublishedMachine(t *testing.T) {
	t.Parallel()
	cr, err := github.LatestConsensusRelease(context.Background())
	Require(t, err)
	machPath := populateMachineDir(t, cr)
	RunChallengeTest(t, false, true, makeBatch_MsgsPerBatch+1, false, false, machPath)
	RunChallengeTest(t, false, true, makeBatch_MsgsPerBatch+1, true, false, machPath)
	RunChallengeTest(t, false, true, makeBatch_MsgsPerBatch+1, true, true, machPath)
}

func TestChallengeManagerFullAsserterCorrect(t *testing.T) {
	t.Parallel()
	defaultWasmRootDir := ""
	RunChallengeTest(t, true, false, makeBatch_MsgsPerBatch+2, false, false, defaultWasmRootDir)
	RunChallengeTest(t, true, false, makeBatch_MsgsPerBatch+2, true, false, defaultWasmRootDir)
	RunChallengeTest(t, true, false, makeBatch_MsgsPerBatch+2, true, true, defaultWasmRootDir)
}

func TestChallengeManagerFullAsserterCorrectWithPublishedMachine(t *testing.T) {
	t.Parallel()
	cr, err := github.LatestConsensusRelease(context.Background())
	Require(t, err)
	machPath := populateMachineDir(t, cr)
	RunChallengeTest(t, true, true, makeBatch_MsgsPerBatch+2, false, false, machPath)
	RunChallengeTest(t, true, true, makeBatch_MsgsPerBatch+2, true, false, machPath)
	RunChallengeTest(t, true, true, makeBatch_MsgsPerBatch+2, true, true, machPath)
}
