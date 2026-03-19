package poc_test

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
)

func TestLogicBugDetection(t *testing.T) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   "linux",
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get("linux", targets.AMD64),
		},
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		t.Fatalf("failed to create reporter: %v", err)
	}

	// Test 1: ContainsCrash should detect SYZLOGIC
	executorOutput := []byte(
		"executing program 1:\n" +
			"SYZLOGIC: read returned 4096 but count is 16\n" +
			"context deadline exceeded\n",
	)
	if !reporter.ContainsCrash(executorOutput) {
		t.Fatal("FAIL: ContainsCrash did not detect SYZLOGIC in output")
	}
	t.Log("PASS: ContainsCrash correctly detects SYZLOGIC")

	// Test 2: Parse should extract the correct title
	rep := reporter.Parse(executorOutput)
	if rep == nil {
		t.Fatal("FAIL: Parse returned nil for SYZLOGIC output")
	}
	if !strings.Contains(rep.Title, "SYZLOGIC") {
		t.Fatalf("FAIL: unexpected title: %q (expected to contain SYZLOGIC)", rep.Title)
	}
	t.Logf("PASS: Parse extracted title: %q", rep.Title)

	// Test 3: Normal output should NOT trigger
	normalOutput := []byte(
		"executing program 1:\n" +
			"#0 [100ms] -> read(0x3, 0x200, 0x10)\n" +
			"#0 [101ms] <- read=0x10 errno=0\n",
	)
	if reporter.ContainsCrash(normalOutput) {
		t.Fatal("FAIL: ContainsCrash false positive on normal output")
	}
	t.Log("PASS: Normal output does NOT trigger false positive")

	// Test 4: SYZFAIL (original syzkaller) should still work
	syzfailOutput := []byte("SYZFAIL: something went wrong\n")
	if !reporter.ContainsCrash(syzfailOutput) {
		t.Fatal("FAIL: ContainsCrash did not detect SYZFAIL")
	}
	t.Log("PASS: SYZFAIL still works alongside SYZLOGIC")
}
