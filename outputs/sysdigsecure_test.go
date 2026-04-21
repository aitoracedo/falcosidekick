// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewSysdigSecurePayload(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	customLabels := map[string]string{"env": "test", "agent": "claudeCode"}
	payload := newSysdigSecurePayload(f, customLabels)

	require.Equal(t, customLabels, payload.CloudsecEvent.Labels)
	require.Len(t, payload.CloudsecEvent.Events, 1)

	event := payload.CloudsecEvent.Events[0]
	require.Equal(t, "Test rule", event.Rule)
	require.Equal(t, "Debug", event.Priority)
	require.Equal(t, "This is a test from falcosidekick", event.Output)
	require.Equal(t, "syscalls", event.Source)
	require.Equal(t, []string{"test", "example"}, event.Tags)
	require.Equal(t, time.Date(2001, 1, 1, 1, 10, 0, 0, time.UTC), event.Timestamp)
}

func TestNewSysdigSecurePayload_EmptyLabels(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	payload := newSysdigSecurePayload(f, nil)

	// nil labels must produce an empty (non-nil) map so the JSON field is always present
	require.NotNil(t, payload.CloudsecEvent.Labels)
	require.Empty(t, payload.CloudsecEvent.Labels)
}
