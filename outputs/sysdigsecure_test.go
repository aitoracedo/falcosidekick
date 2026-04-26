// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

// TestNewSysdigSecurePayload verifies that newSysdigSecurePayload correctly
// maps a FalcoPayload to the flat {labels, events} structure expected by
// POST /api/v1/eventsDispatch/ingest.
func TestNewSysdigSecurePayload(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	customLabels := map[string]string{"env": "test", "agent": "claudeCode"}
	payload := newSysdigSecurePayload(f, customLabels)

	require.Equal(t, customLabels, payload.Labels)
	require.Len(t, payload.Events, 1)

	event := payload.Events[0]
	require.Equal(t, "Test rule", event.Rule)
	require.Equal(t, "Debug", event.Priority)
	require.Equal(t, "This is a test from falcosidekick", event.Output)
	require.Equal(t, "syscalls", event.Source)
	require.Equal(t, []string{"test", "example"}, event.Tags)
	require.Equal(t, time.Date(2001, 1, 1, 1, 10, 0, 0, time.UTC), event.Timestamp)
}

// TestNewSysdigSecurePayload_EmptyLabels verifies that nil custom labels produce
// an empty (non-nil) map so the JSON field is always present in the payload.
func TestNewSysdigSecurePayload_EmptyLabels(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	payload := newSysdigSecurePayload(f, nil)

	require.NotNil(t, payload.Labels)
	require.Empty(t, payload.Labels)
}
