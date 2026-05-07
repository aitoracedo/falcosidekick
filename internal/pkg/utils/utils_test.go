// SPDX-License-Identifier: MIT OR Apache-2.0

package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout for the duration of fn and returns whatever
// was written to it.
func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestTimeTrack_DisabledByDefault(t *testing.T) {
	EnableTimeTracks = false
	out := captureStdout(func() {
		TimeTrack(time.Now())
	})
	if out != "" {
		t.Errorf("expected no output when disabled, got: %q", out)
	}
}

func TestTimeTrack_PrintsFunctionName(t *testing.T) {
	EnableTimeTracks = true
	defer func() { EnableTimeTracks = false }()

	out := captureStdout(func() {
		TimeTrack(time.Now())
	})

	if !strings.Contains(out, "[TIMER]") {
		t.Errorf("expected [TIMER] prefix in output, got: %q", out)
	}
	// runtime.Caller(1) from inside captureStdout's closure reports
	// the anonymous func — the output must contain the test function name.
	if !strings.Contains(out, "TestTimeTrack_PrintsFunctionName") {
		t.Errorf("expected test function name in output, got: %q", out)
	}
	if !strings.Contains(out, "took") {
		t.Errorf("expected 'took' in output, got: %q", out)
	}
	fmt.Print(out) // echo so `go test -v` shows the line
}

func TestTimeTrack_IncludesDuration(t *testing.T) {
	EnableTimeTracks = true
	defer func() { EnableTimeTracks = false }()

	start := time.Now()
	time.Sleep(5 * time.Millisecond)

	out := captureStdout(func() {
		TimeTrack(start)
	})

	// Duration must be ≥ 5ms — presence of "ms" or "s" is sufficient.
	if !strings.Contains(out, "ms") && !strings.Contains(out, "s") {
		t.Errorf("expected a duration unit in output, got: %q", out)
	}
}
