// Copyright Stealth Scale B.V. 2026
// SPDX-License-Identifier: MIT

package gcopt_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/stealth-scale/go-zeroalloc/gcopt"
)

func TestGcopt(t *testing.T) {
	t.Parallel()

	t.Run("Analyzer", func(t *testing.T) {
		t.Parallel()

		analysistest.Run(t, analysistest.TestData(), gcopt.Analyzer, "alloc")
	})
}

// TestGcoptFlags sets flags of the analyzer, which are package variables, so it does not run
// in parallel. Go runs it before the parallel tests resume.
func TestGcoptFlags(t *testing.T) {
	t.Run("Analyzer", func(t *testing.T) {
		for _, name := range []string{"writebarriers", "conditional"} {
			if err := gcopt.Analyzer.Flags.Set(name, "true"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := gcopt.Analyzer.Flags.Set(name, "false"); err != nil {
					t.Error(err)
				}
			})
		}

		analysistest.Run(t, analysistest.TestData(), gcopt.Analyzer, "flags")
	})
}
