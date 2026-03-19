// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RCAResult holds the root cause analysis for a crash.
type RCAResult struct {
	CrashTitle    string    `json:"crash_title"`
	AnalyzedAt    time.Time `json:"analyzed_at"`
	BugCategory   string    `json:"bug_category"`   // e.g. "Logic Bug", "Memory Safety", "Concurrency", etc.
	RootCause     string    `json:"root_cause"`      // Human-readable root cause summary.
	Syscall       string    `json:"syscall"`          // The guilty syscall (if identifiable).
	Details       string    `json:"details"`          // Detailed explanation.
	Severity      string    `json:"severity"`         // "high", "medium", "low"
	Reproduction  string    `json:"reproduction"`     // Summary of repro program if available.
	Suggestion    string    `json:"suggestion"`       // Suggested fix direction.
	GuiltyFile    string    `json:"guilty_file"`      // Source file from report, if available.
}

const rcaFileName = "rca.json"

// RunRCA performs root cause analysis on the crash identified by crashID.
// It reads the crash description, report, and reproducer, then produces a structured analysis.
func RunRCA(workdir, crashID string) (*RCAResult, error) {
	dir := filepath.Join(workdir, "crashes", crashID)

	desc, err := os.ReadFile(filepath.Join(dir, "description"))
	if err != nil {
		return nil, fmt.Errorf("failed to read crash description: %w", err)
	}
	title := strings.TrimSpace(string(desc))

	// Read optional files.
	reportData, _ := os.ReadFile(filepath.Join(dir, "repro.report"))
	reproData, _ := os.ReadFile(filepath.Join(dir, "repro.prog"))

	// Try numbered report files if repro.report doesn't exist.
	if len(reportData) == 0 {
		reportData, _ = os.ReadFile(filepath.Join(dir, "report0"))
	}

	result := &RCAResult{
		CrashTitle: title,
		AnalyzedAt: time.Now(),
	}

	// Classify and analyze based on crash title patterns.
	analyzeCrashTitle(result, title)

	// Extract info from report text.
	if len(reportData) > 0 {
		analyzeReport(result, string(reportData))
	}

	// Analyze reproducer program.
	if len(reproData) > 0 {
		analyzeRepro(result, string(reproData))
	}

	// Save result to disk.
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RCA result: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, rcaFileName), jsonData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write RCA result: %w", err)
	}

	return result, nil
}

// LoadRCA loads a previously saved RCA result for the given crash.
func LoadRCA(workdir, crashID string) (*RCAResult, error) {
	data, err := os.ReadFile(filepath.Join(workdir, "crashes", crashID, rcaFileName))
	if err != nil {
		return nil, err
	}
	var result RCAResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse RCA result: %w", err)
	}
	return &result, nil
}

var syzlogicRe = regexp.MustCompile(`SYZLOGIC:\s*(\w+)\s+returned\s+(\S+)\s+but\s+count\s+is\s+(\S+)`)

func analyzeCrashTitle(result *RCAResult, title string) {
	switch {
	case strings.HasPrefix(title, "SYZLOGIC:"):
		result.BugCategory = "Logic Bug"
		result.Severity = "high"
		if m := syzlogicRe.FindStringSubmatch(title); m != nil {
			result.Syscall = m[1]
			result.RootCause = fmt.Sprintf(
				"Kernel syscall %s returned %s bytes but the caller only requested %s bytes.",
				m[1], m[2], m[3])
			result.Details = fmt.Sprintf(
				"The kernel's implementation of %s violated the POSIX invariant that an I/O syscall "+
					"must never return more bytes than requested. This typically indicates a buffer overread "+
					"or information leak in the kernel driver handling this file descriptor. "+
					"The return value (%s) exceeds the count argument (%s).",
				m[1], m[2], m[3])
			result.Suggestion = fmt.Sprintf(
				"Inspect the kernel source for the %s handler of the file descriptor involved. "+
					"Look for incorrect length calculations in the driver's read/write path. "+
					"Check if the driver correctly clamps the return value to min(count, available_data).",
				m[1])
		} else {
			result.RootCause = "Kernel I/O syscall returned more data than requested (POSIX invariant violation)."
			result.Details = "A SYZLOGIC bug was detected but the specific syscall details could not be parsed."
			result.Suggestion = "Review the crash log and report for the specific syscall and file descriptor involved."
		}

	case strings.Contains(title, "KASAN"):
		result.BugCategory = "Memory Safety"
		result.Severity = "high"
		if strings.Contains(title, "use-after-free") {
			result.RootCause = "Use-after-free memory access detected by KASAN."
			result.Details = "A kernel code path accessed memory that was previously freed. " +
				"This can lead to data corruption, information leaks, or privilege escalation."
			result.Suggestion = "Check object lifetime management. Look for missing reference counting " +
				"or races between free and access paths."
		} else if strings.Contains(title, "out-of-bounds") || strings.Contains(title, "slab-out-of-bounds") {
			result.RootCause = "Out-of-bounds memory access detected by KASAN."
			result.Details = "A kernel code path read or wrote beyond the allocated buffer boundary."
			result.Suggestion = "Check buffer size calculations and array index bounds in the guilty function."
		} else {
			result.RootCause = "Memory safety violation detected by KASAN."
			result.Details = "KASAN detected an invalid memory access in the kernel."
			result.Suggestion = "Examine the stack trace in the crash report to identify the guilty code path."
		}

	case strings.Contains(title, "KMSAN"):
		result.BugCategory = "Memory Safety"
		result.Severity = "medium"
		result.RootCause = "Uninitialized memory usage detected by KMSAN."
		result.Details = "The kernel used uninitialized memory, potentially leaking stack/heap data to userspace."
		result.Suggestion = "Ensure all buffers are properly initialized before being copied to userspace or used in decisions."

	case strings.Contains(title, "KCSAN"):
		result.BugCategory = "Concurrency"
		result.Severity = "medium"
		result.RootCause = "Data race detected by KCSAN."
		result.Details = "Concurrent unsynchronized access to shared data was detected in the kernel."
		result.Suggestion = "Add appropriate locking or use READ_ONCE/WRITE_ONCE for the racy accesses."

	case strings.HasPrefix(title, "WARNING:"):
		result.BugCategory = "Kernel Warning"
		result.Severity = "medium"
		result.RootCause = "Kernel warning triggered, indicating an unexpected but non-fatal condition."
		result.Details = "A WARN_ON or similar assertion fired in the kernel."
		result.Suggestion = "Examine the warning condition and the code path that led to it."

	case strings.HasPrefix(title, "BUG:"):
		result.BugCategory = "Kernel Bug"
		result.Severity = "high"
		if strings.Contains(title, "unable to handle") {
			result.RootCause = "Null pointer dereference or invalid memory access."
			result.Details = "The kernel attempted to access an invalid memory address."
			result.Suggestion = "Check for null pointer checks on the object accessed in the crash stack trace."
		} else {
			result.RootCause = "Kernel BUG() assertion triggered."
			result.Details = "A BUG_ON assertion in the kernel code was hit."
			result.Suggestion = "Examine the BUG_ON condition in the source to understand what invariant was violated."
		}

	case strings.Contains(title, "deadlock"):
		result.BugCategory = "Concurrency"
		result.Severity = "high"
		result.RootCause = "Potential deadlock detected by lockdep."
		result.Details = "The kernel lock dependency checker detected a lock ordering violation."
		result.Suggestion = "Review the lock acquisition order in the involved code paths."

	case strings.Contains(title, "memory leak"):
		result.BugCategory = "Resource Leak"
		result.Severity = "low"
		result.RootCause = "Kernel memory leak detected by kmemleak."
		result.Details = "Allocated memory was not freed on the expected code path."
		result.Suggestion = "Add proper cleanup/free calls on error and normal exit paths."

	default:
		result.BugCategory = "Other"
		result.Severity = "medium"
		result.RootCause = "Crash detected: " + title
		result.Details = "The crash type could not be automatically classified. Review the crash report and log manually."
		result.Suggestion = "Examine the crash report for stack trace and context."
	}
}

var (
	callTraceRe = regexp.MustCompile(`(?m)^\s*(\w+)\+0x[0-9a-f]+/0x[0-9a-f]+`)
	fileLineRe  = regexp.MustCompile(`([a-zA-Z0-9_/]+\.\w+:\d+)`)
)

func analyzeReport(result *RCAResult, reportText string) {
	// Extract guilty file from call trace.
	if result.GuiltyFile == "" {
		if matches := fileLineRe.FindAllString(reportText, 5); len(matches) > 0 {
			result.GuiltyFile = matches[0]
		}
	}

	// Enrich details with call trace functions.
	if funcs := callTraceRe.FindAllStringSubmatch(reportText, 10); len(funcs) > 0 {
		var funcNames []string
		for _, m := range funcs {
			funcNames = append(funcNames, m[1])
		}
		result.Details += fmt.Sprintf("\n\nCall trace (top functions): %s", strings.Join(funcNames, " -> "))
	}
}

func analyzeRepro(result *RCAResult, reproText string) {
	lines := strings.Split(strings.TrimSpace(reproText), "\n")
	var syscalls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract syscall name (first token before '(').
		if idx := strings.Index(line, "("); idx > 0 {
			name := strings.TrimPrefix(line, "r0 = ")
			name = strings.TrimPrefix(name, "r1 = ")
			name = strings.TrimPrefix(name, "r2 = ")
			if eqIdx := strings.Index(name, " = "); eqIdx > 0 {
				name = name[eqIdx+3:]
			}
			if parenIdx := strings.Index(name, "("); parenIdx > 0 {
				syscalls = append(syscalls, name[:parenIdx])
			}
		}
	}
	if len(syscalls) > 0 {
		result.Reproduction = fmt.Sprintf("Reproducer uses %d syscalls: %s",
			len(syscalls), strings.Join(syscalls, ", "))
	}
}
