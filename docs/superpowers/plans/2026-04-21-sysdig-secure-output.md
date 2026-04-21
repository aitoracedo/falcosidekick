# Sysdig Secure Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `SysdigSecure` output to falcosidekick that forwards Falco events to `POST <url>/api/eventsDispatcher/v2/ingest` using the `AuditMsg` / `eventCollection` payload format with Bearer token auth.

**Architecture:** Follow the standard falcosidekick HTTP-output pattern — no new dependencies. The output is enabled by setting `sysdigsecure.apitoken` in config (or `SYSDIGSECURE_APITOKEN` env var). Each Falco event is POSTed individually, wrapped in `{ "cloudsecEvent": { "labels": {...}, "events": [{...}] } }`. Static labels are configurable per-deployment.

**Tech Stack:** Go 1.21+, `github.com/falcosecurity/falcosidekick` module, `github.com/stretchr/testify/require` for tests, Viper for config.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `types/types.go` | Modify | Add `SysdigSecureOutputConfig` struct, `Configuration.SysdigSecure` field, `Statistics.SysdigSecure` field |
| `stats.go` | Modify | Register `SysdigSecure` expvar map |
| `config.go` | Modify | Add `SysdigSecure` entry in `httpOutputDefaults` |
| `outputs/sysdigsecure.go` | Create | Payload types, `newSysdigSecurePayload()`, `SysdigSecurePost()` |
| `outputs/sysdigsecure_test.go` | Create | Unit tests for payload construction and headers |
| `main.go` | Modify | Declare `sysdigSecureClient`, initialize it in `init()` |
| `handlers.go` | Modify | Dispatch `sysdigSecureClient.SysdigSecurePost()` in `forwardEvent()` |
| `config_example.yaml` | Modify | Document the `sysdigsecure` config block |

---

## Task 1: Add types, stats entry, and config defaults

**Files:**
- Modify: `types/types.go`
- Modify: `stats.go`
- Modify: `config.go`

- [ ] **Step 1: Add `SysdigSecureOutputConfig` to `types/types.go`**

In `types/types.go`, add the config struct. Place it at the end of the config structs section (after `LogstashConfig`, before `Statistics`):

```go
// SysdigSecureOutputConfig represents parameters for Sysdig Secure
type SysdigSecureOutputConfig struct {
	CommonConfig    `mapstructure:",squash"`
	APIToken        string
	URL             string
	CustomLabels    map[string]string
	MinimumPriority string
}
```

- [ ] **Step 2: Add `SysdigSecure` field to `Configuration` in `types/types.go`**

In the `Configuration` struct (around line 124, after `Splunk SplunkOutputConfig`), add:

```go
SysdigSecure SysdigSecureOutputConfig
```

- [ ] **Step 3: Add `SysdigSecure` field to `Statistics` in `types/types.go`**

In the `Statistics` struct (around line 940, after `Splunk *expvar.Map`), add:

```go
SysdigSecure *expvar.Map
```

- [ ] **Step 4: Register the stats map in `stats.go`**

In `getInitStats()` in `stats.go`, after `Splunk: getOutputNewMap("splunk"),`, add:

```go
SysdigSecure: getOutputNewMap("sysdigsecure"),
```

- [ ] **Step 5: Add defaults to `config.go`**

In `config.go`, in the `httpOutputDefaults` map (after the `"Splunk"` entry, before the closing `}`), add:

```go
"SysdigSecure": {
    "APIToken":        "",
    "URL":             "https://prodmon.app.sysdig.com/secure",
    "MinimumPriority": "",
},
```

- [ ] **Step 6: Build to verify no compile errors**

```bash
cd ~/work/falcosidekick
go build ./...
```

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add types/types.go stats.go config.go
git commit -m "feat(sysdigsecure): add config type, stats entry, and config defaults"
```

---

## Task 2: Write failing tests

**Files:**
- Create: `outputs/sysdigsecure_test.go`

- [ ] **Step 1: Create the test file**

Create `outputs/sysdigsecure_test.go` with the following content. This follows the established pattern in the codebase (e.g. `dynatrace_test.go`, `splunk_test.go`) — only test the payload construction function; header behavior is validated via the smoke test in Task 7.

```go
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
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd ~/work/falcosidekick
go test ./outputs/ -run TestNewSysdigSecure -v
```

Expected: compilation error — `newSysdigSecurePayload` undefined. This confirms the tests are correctly targeting missing code.

---

## Task 3: Implement `outputs/sysdigsecure.go`

**Files:**
- Create: `outputs/sysdigsecure.go`

- [ ] **Step 1: Create the implementation file**

Create `outputs/sysdigsecure.go`:

```go
// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

type sysdigSecureEvent struct {
	Timestamp    time.Time              `json:"timestamp"`
	Rule         string                 `json:"rule"`
	Priority     string                 `json:"priority"`
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Source       string                 `json:"source,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
}

type sysdigSecureEventCollection struct {
	Labels map[string]string   `json:"labels"`
	Events []sysdigSecureEvent `json:"events"`
}

type sysdigSecurePayload struct {
	CloudsecEvent sysdigSecureEventCollection `json:"cloudsecEvent"`
}

func newSysdigSecurePayload(falcopayload types.FalcoPayload, customLabels map[string]string) sysdigSecurePayload {
	labels := make(map[string]string)
	for k, v := range customLabels {
		labels[k] = v
	}

	event := sysdigSecureEvent{
		Timestamp:    falcopayload.Time,
		Rule:         falcopayload.Rule,
		Priority:     falcopayload.Priority.String(),
		Output:       falcopayload.Output,
		OutputFields: falcopayload.OutputFields,
		Source:       falcopayload.Source,
		Tags:         falcopayload.Tags,
	}

	return sysdigSecurePayload{
		CloudsecEvent: sysdigSecureEventCollection{
			Labels: labels,
			Events: []sysdigSecureEvent{event},
		},
	}
}

// SysdigSecurePost posts a Falco event to the Sysdig Secure Events API
func (c *Client) SysdigSecurePost(falcopayload types.FalcoPayload) {
	c.Stats.SysdigSecure.Add(Total, 1)

	token := c.Config.SysdigSecure.APIToken
	optfn := func(req *http.Request) {
		req.Header.Set(AuthorizationHeaderKey, Bearer+" "+token)
		req.Header.Set("X-Sysdig-Product", "SDS")
	}

	err := c.Post(newSysdigSecurePayload(falcopayload, c.Config.SysdigSecure.CustomLabels), optfn)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:sysdigsecure", "status:error"})
		c.Stats.SysdigSecure.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "sysdigsecure", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "sysdigsecure"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:sysdigsecure", "status:ok"})
	c.Stats.SysdigSecure.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sysdigsecure", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "sysdigsecure"),
		attribute.String("status", OK)).Inc()
}
```

- [ ] **Step 2: Run the tests to confirm they pass**

```bash
cd ~/work/falcosidekick
go test ./outputs/ -run TestNewSysdigSecure -v
go test ./outputs/ -run TestSysdigSecurePost -v
```

Expected output:
```
--- PASS: TestNewSysdigSecurePayload (0.00s)
--- PASS: TestNewSysdigSecurePayload_EmptyLabels (0.00s)
--- PASS: TestSysdigSecurePost_Headers (0.00s)
PASS
```

- [ ] **Step 3: Run the full test suite to check for regressions**

```bash
go test ./...
```

Expected: all existing tests continue to pass.

- [ ] **Step 4: Commit**

```bash
git add outputs/sysdigsecure.go outputs/sysdigsecure_test.go
git commit -m "feat(sysdigsecure): implement payload types, SysdigSecurePost, and tests"
```

---

## Task 4: Wire up client init in `main.go`

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Declare the global client variable**

In `main.go`, in the `var (...)` block (around line 86, after `splunkClient *outputs.Client`), add:

```go
sysdigSecureClient *outputs.Client
```

- [ ] **Step 2: Add the init block**

In `main.go`, in the `init()` function, after the Splunk init block (around line 891):

```go
if config.SysdigSecure.APIToken != "" {
    var err error
    endpointURL := strings.TrimRight(config.SysdigSecure.URL, "/") + "/api/eventsDispatcher/v2/ingest"
    sysdigSecureClient, err = outputs.NewClient("SysdigSecure", endpointURL, config.SysdigSecure.CommonConfig, *initClientArgs)
    if err != nil {
        config.SysdigSecure.APIToken = ""
    } else {
        outputs.EnabledOutputs = append(outputs.EnabledOutputs, "SysdigSecure")
    }
}
```

`strings` is already imported in `main.go` — no new import needed.

- [ ] **Step 3: Build to verify**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add main.go
git commit -m "feat(sysdigsecure): initialize client in main.go"
```

---

## Task 5: Wire up event dispatch in `handlers.go`

**Files:**
- Modify: `handlers.go`

- [ ] **Step 1: Add the dispatch call**

In `handlers.go`, in `forwardEvent()`, after the final closing brace of the Logstash block (line 566, the last `}` before the function closes), add:

```go
if config.SysdigSecure.APIToken != "" && (falcopayload.Priority >= types.Priority(config.SysdigSecure.MinimumPriority) || falcopayload.Rule == testRule) {
    go sysdigSecureClient.SysdigSecurePost(falcopayload)
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 3: Run all tests**

```bash
go test ./...
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add handlers.go
git commit -m "feat(sysdigsecure): dispatch SysdigSecurePost in forwardEvent"
```

---

## Task 6: Document the config and update `config_example.yaml`

**Files:**
- Modify: `config_example.yaml`

- [ ] **Step 1: Append the sysdigsecure block**

At the end of `config_example.yaml` (after the `logstash:` block), add:

```yaml

sysdigsecure:
  # apitoken: "" # Sysdig Secure API token. If not empty, Sysdig Secure output is enabled. Env var: SYSDIGSECURE_APITOKEN
  # url: "" # Sysdig Secure base URL (default: https://prodmon.app.sysdig.com/secure)
  # customlabels: # static labels added to every event (map type, must be set in config file)
  #   environment: "production"
  #   cluster: "my-cluster"
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
  # checkcert: true # check if ssl certificate of the output is valid (default: true)
```

- [ ] **Step 2: Commit**

```bash
git add config_example.yaml
git commit -m "docs(sysdigsecure): add sysdigsecure config block to config_example.yaml"
```

---

## Task 7: Build, smoke test, and verify

- [ ] **Step 1: Final build**

```bash
cd ~/work/falcosidekick
go build ./...
```

Expected: clean build.

- [ ] **Step 2: Run the full test suite**

```bash
go test ./...
```

Expected: all tests pass, including the three new `TestNewSysdigSecure*` and `TestSysdigSecurePost*` tests.

- [ ] **Step 3: Smoke test with `/test` endpoint**

Create a minimal `config.yaml` (in the falcosidekick directory, do **not** commit it — it contains a real token):

```yaml
sysdigsecure:
  apitoken: "<your-sysdig-secure-api-token>"
  url: "https://prodmon.app.sysdig.com/secure"
  customlabels:
    agent: "claudeCode"
  minimumpriority: "debug"
  checkcert: true
```

Start falcosidekick:

```bash
./falcosidekick -config config.yaml
```

Confirm in the startup log:

```
Enabled Outputs: [SysdigSecure]
Falcosidekick is up and listening on 0.0.0.0:2801
```

In a second terminal, fire a synthetic test event:

```bash
curl -s -X POST http://localhost:2801/test
```

Expected falcosidekick log line:

```
[SysdigSecure] POST OK (200)
```

Verify the event appears in the Sysdig Secure UI with `labels.agent: claudeCode`.

- [ ] **Step 4: Test the full fan-out setup with coding-agents-kit**

Add `config.yaml` to `.gitignore` to prevent accidental token commit:

```bash
echo "config.yaml" >> .gitignore
git add .gitignore
git commit -m "chore: ignore local config.yaml (contains secrets)"
```

Add the Webhook output to `config.yaml` to fan-out to the coding-agents-kit plugin:

```yaml
sysdigsecure:
  apitoken: "<your-sysdig-secure-api-token>"
  url: "https://prodmon.app.sysdig.com/secure"
  customlabels:
    agent: "claudeCode"
  minimumpriority: "debug"
  checkcert: true

webhook:
  address: "http://127.0.0.1:2802"
  minimumpriority: "debug"
```

Create `~/.coding-agents-kit/config/falco.http_output_override.yaml`:

```yaml
http_output:
  enabled: true
  url: http://127.0.0.1:2801
```

Add it to `~/.coding-agents-kit/config/falco.yaml` under `config_files`:

```yaml
config_files:
  - ${HOME}/.coding-agents-kit/config/falco.coding_agents_plugin.yaml
  - ${HOME}/.coding-agents-kit/config/falco.http_output_override.yaml
```

Falco watches config files and restarts automatically. Use any tool call from Claude Code to trigger a Falco alert, then confirm in falcosidekick logs:

```
[SysdigSecure] POST OK (200)
[Webhook] POST OK (200)
```

And the event appears in Sysdig Secure with `labels.agent: claudeCode`.
