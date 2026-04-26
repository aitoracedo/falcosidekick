# BigQuery

- **Category**: Logs
- **Website**: https://cloud.google.com/bigquery

## Table of content

- [BigQuery](#bigquery)
  - [Table of content](#table-of-content)
  - [Configuration](#configuration)
  - [Example of config.yaml](#example-of-configyaml)
  - [Additional info](#additional-info)
    - [Event row schema](#event-row-schema)
    - [Replicating the test environment](#replicating-the-test-environment)
    - [Installing the bq CLI](#installing-the-bq-cli)
      - [macOS](#macos)
      - [Linux](#linux)
    - [GCP provisioning](#gcp-provisioning)
      - [1. Create a service account](#1-create-a-service-account)
      - [2. Create the dataset](#2-create-the-dataset)
      - [3. Create the table](#3-create-the-table)
      - [4. Grant dataset access to the service account](#4-grant-dataset-access-to-the-service-account)
      - [5. Download the service account key](#5-download-the-service-account-key)
    - [Verifying ingestion](#verifying-ingestion)
  - [Integration test results](#integration-test-results)

## Configuration

| Setting | Env var | Default value | Description |
| ------- | ------- | ------------- | ----------- |
| `bigquery.projectid` | `BIGQUERY_PROJECTID` | | GCP project ID, if not empty, BigQuery output is **enabled** |
| `bigquery.datasetid` | `BIGQUERY_DATASETID` | | BigQuery dataset ID |
| `bigquery.tableid` | `BIGQUERY_TABLEID` | | BigQuery table ID |
| `bigquery.servicecredentials` | `BIGQUERY_SERVICECREDENTIALS` | | Path to a service account JSON key file, or the raw JSON content of the key |
| `bigquery.serviceurl` | `BIGQUERY_SERVICEURL` | `https://bigquery.googleapis.com` | BigQuery API base URL. Override for local emulators or private endpoints |
| `bigquery.customlabels` | `BIGQUERY_CUSTOMLABELS` | | Extra key-value pairs added as columns to every row |
| `bigquery.minimumpriority` | `BIGQUERY_MINIMUMPRIORITY` | `""` (= `debug`) | Minimum priority of event for using this output, order is `emergency,alert,critical,error,warning,notice,informational,debug or ""` |

> [!NOTE]
> The Env var values override the settings from yaml file.

> [!NOTE]
> `servicecredentials` accepts either a file path (e.g. `/etc/secrets/sa-key.json`) or the inline
> JSON content of the key. If the value starts with `{` it is treated as inline JSON; otherwise it
> is read from the file path given.

## Example of config.yaml

```yaml
bigquery:
  # projectid: "" # GCP project ID, if not empty, BigQuery output is enabled
  # datasetid: "" # BigQuery dataset ID
  # tableid: "" # BigQuery table ID
  # servicecredentials: "" # path to a service account JSON key file, or inline JSON content
  # serviceurl: "https://bigquery.googleapis.com" # BigQuery API base URL (default)
  # customlabels: # extra columns added to every row
  #   environment: production
  #   team: security
  # minimumpriority: "" # minimum priority of event for using this output, order is emergency|alert|critical|error|warning|notice|informational|debug or "" (default)
```

## Additional info

Events are sent via the BigQuery [tabledata.insertAll](https://cloud.google.com/bigquery/docs/reference/rest/v2/tabledata/insertAll)
streaming API (one row per Falco event). Authentication uses a GCP service account key with the
`https://www.googleapis.com/auth/bigquery.insertdata` OAuth2 scope.

### Event row schema

Each row contains the following flat columns. `output_fields` and `tags` are JSON-serialized
strings so the table schema stays simple regardless of the dynamic fields Falco produces.

| Column | BigQuery type | Description |
| ------ | ------------- | ----------- |
| `timestamp` | `TIMESTAMP` | Event time in UTC |
| `rule` | `STRING` | Falco rule name |
| `priority` | `STRING` | Event priority (`warning`, `error`, etc.) |
| `output` | `STRING` | Full Falco output string |
| `output_fields` | `STRING` | JSON-serialized map of Falco output fields |
| `source` | `STRING` | Event source (`syscall`, `k8s_audit`, etc.) |
| `tags` | `STRING` | JSON-serialized array of rule tags |
| *(custom labels)* | `STRING` | Any key configured under `customlabels` |

### Replicating the test environment

The script below provisions everything required in a fresh GCP project so that any team can
run a functional falcosidekick → BigQuery pipeline from scratch. It creates the service account,
dataset, table (with the exact schema used in production), grants the required IAM role, and
downloads the key file — all in one go.

> [!NOTE]
> Prerequisites: `gcloud` CLI installed and authenticated (`gcloud auth login`).
> The `bq` CLI is bundled with the Google Cloud SDK — see
> [Installing the bq CLI](#installing-the-bq-cli) if it is missing.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ── Configuration — edit these three variables ──────────────────────────────
PROJECT_ID="your-gcp-project-id"     # GCP project where BigQuery will live
DATASET="falco_events"               # BigQuery dataset name
TABLE="events"                       # BigQuery table name
# ─────────────────────────────────────────────────────────────────────────────

SA_NAME="falcosidekick-bq"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="${HOME}/falcosidekick-bq-key.json"

echo "==> Setting default project to ${PROJECT_ID}"
gcloud config set project "${PROJECT_ID}"

echo "==> Creating service account ${SA_EMAIL}"
gcloud iam service-accounts create "${SA_NAME}" \
  --project="${PROJECT_ID}" \
  --display-name="Falcosidekick BigQuery writer" \
  2>/dev/null || echo "    (service account already exists, continuing)"

echo "==> Creating dataset ${DATASET}"
bq mk --project_id="${PROJECT_ID}" --location=US "${DATASET}" \
  2>/dev/null || echo "    (dataset already exists, continuing)"

echo "==> Creating table ${DATASET}.${TABLE} with required schema"
bq mk --project_id="${PROJECT_ID}" \
  --table "${DATASET}.${TABLE}" \
  --schema \
  'timestamp:TIMESTAMP,rule:STRING,priority:STRING,output:STRING,output_fields:STRING,source:STRING,tags:STRING' \
  2>/dev/null || echo "    (table already exists, continuing)"

echo "==> Granting roles/bigquery.dataEditor to ${SA_EMAIL} on dataset ${DATASET}"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.dataEditor" \
  --condition=None \
  --quiet

echo "==> Downloading service account key to ${KEY_FILE}"
gcloud iam service-accounts keys create "${KEY_FILE}" \
  --iam-account="${SA_EMAIL}" \
  --project="${PROJECT_ID}"
chmod 600 "${KEY_FILE}"

echo ""
echo "Done. Add the following block to your falcosidekick config.yaml:"
echo ""
echo "bigquery:"
echo "  projectid: \"${PROJECT_ID}\""
echo "  datasetid: \"${DATASET}\""
echo "  tableid: \"${TABLE}\""
echo "  servicecredentials: \"${KEY_FILE}\""
echo "  minimumpriority: \"debug\""
```

Save the script to a file (e.g. `setup-bigquery.sh`), set `PROJECT_ID` to your GCP project,
then run:

```bash
chmod +x setup-bigquery.sh
./setup-bigquery.sh
```

The script is idempotent — running it again on an existing environment skips already-created
resources and only applies missing ones.

> [!NOTE]
> **Linux only:** if the user running the script does not have write permission to `${HOME}`,
> the key download step will fail. In that case, set `KEY_FILE` at the top of the script to a
> path the user owns (e.g. `/tmp/falcosidekick-bq-key.json`), run the script, then move the
> key to its final location and update `servicecredentials` in `config.yaml` accordingly:
> ```bash
> KEY_FILE="/tmp/falcosidekick-bq-key.json"   # change in the script before running
> # after the script completes:
> mv /tmp/falcosidekick-bq-key.json /your/target/path/falcosidekick-bq-key.json
> chmod 600 /your/target/path/falcosidekick-bq-key.json
> ```

#### Table schema reference

The table schema created by the script above. All columns are `NULLABLE STRING` except
`timestamp` which is `NULLABLE TIMESTAMP`.

```json
[
  {"name": "timestamp",     "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "rule",          "type": "STRING",    "mode": "NULLABLE"},
  {"name": "priority",      "type": "STRING",    "mode": "NULLABLE"},
  {"name": "output",        "type": "STRING",    "mode": "NULLABLE"},
  {"name": "output_fields", "type": "STRING",    "mode": "NULLABLE"},
  {"name": "source",        "type": "STRING",    "mode": "NULLABLE"},
  {"name": "tags",          "type": "STRING",    "mode": "NULLABLE"}
]
```

`output_fields` is a JSON-serialized string (e.g. `{"proc.name":"curl","user.name":"root"}`).
`tags` is a JSON-serialized array (e.g. `["network","outbound"]`). Both are stored as plain
strings so the schema stays flat regardless of the dynamic fields Falco produces.

If you add `customlabels` to your falcosidekick config, add a matching `STRING NULLABLE` column
for each label key before writing events:

```bash
# Example: add an "environment" label column
bq query --project_id="${PROJECT_ID}" --nouse_legacy_sql \
  "ALTER TABLE ${DATASET}.${TABLE} ADD COLUMN IF NOT EXISTS environment STRING"
```

### Installing the bq CLI

`bq` is bundled with the Google Cloud SDK — the same package that provides `gcloud`. If `gcloud`
is already installed, check whether `bq` is available with `which bq`. If it is missing, the full
SDK was not installed; use the steps below to add it.

There is no native `gcloud` subcommand for querying BigQuery data. The REST API alternative
(using `curl` and `gcloud auth print-access-token`) is shown alongside each `bq` command
throughout this document as a drop-in replacement that requires no additional installation.

#### macOS

**Homebrew (recommended):**

```bash
brew install --cask google-cloud-sdk
```

**Manual install (Apple Silicon):**

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-arm.tar.gz
tar -xf google-cloud-cli-darwin-arm.tar.gz
./google-cloud-sdk/install.sh
source ~/.zshrc
```

**Manual install (Intel):**

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-darwin-x86_64.tar.gz
tar -xf google-cloud-cli-darwin-x86_64.tar.gz
./google-cloud-sdk/install.sh
source ~/.zshrc
```

#### Linux

**Debian / Ubuntu (apt):**

```bash
sudo apt-get install apt-transport-https ca-certificates gnupg
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
  | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
  | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-sdk
```

**Manual install (x86_64):**

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh
source ~/.bashrc
```

**Manual install (ARM64):**

```bash
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-arm.tar.gz
tar -xf google-cloud-cli-linux-arm.tar.gz
./google-cloud-sdk/install.sh
source ~/.bashrc
```

After installing, authenticate and set the default project:

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### GCP provisioning

The steps below use the `gcloud` and `bq` CLIs. REST API equivalents using
`gcloud auth print-access-token` are included where useful.

#### 1. Create a service account

```bash
gcloud iam service-accounts create falcosidekick-bq \
  --project=YOUR_PROJECT_ID \
  --display-name="Falcosidekick BigQuery writer"
```

#### 2. Create the dataset

```bash
bq mk --project_id=YOUR_PROJECT_ID --location=US falco_events
```

REST equivalent:

```bash
curl -X POST \
  "https://bigquery.googleapis.com/bigquery/v2/projects/YOUR_PROJECT_ID/datasets" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{
    "datasetReference": {
      "projectId": "YOUR_PROJECT_ID",
      "datasetId": "falco_events"
    }
  }'
```

#### 3. Create the table

```bash
bq mk --project_id=YOUR_PROJECT_ID \
  --table falco_events.events \
  'timestamp:TIMESTAMP,rule:STRING,priority:STRING,output:STRING,output_fields:STRING,source:STRING,tags:STRING'
```

REST equivalent:

```bash
curl -X POST \
  "https://bigquery.googleapis.com/bigquery/v2/projects/YOUR_PROJECT_ID/datasets/falco_events/tables" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{
    "tableReference": {
      "projectId": "YOUR_PROJECT_ID",
      "datasetId": "falco_events",
      "tableId": "events"
    },
    "schema": {
      "fields": [
        {"name": "timestamp",     "type": "TIMESTAMP", "mode": "NULLABLE"},
        {"name": "rule",          "type": "STRING",    "mode": "NULLABLE"},
        {"name": "priority",      "type": "STRING",    "mode": "NULLABLE"},
        {"name": "output",        "type": "STRING",    "mode": "NULLABLE"},
        {"name": "output_fields", "type": "STRING",    "mode": "NULLABLE"},
        {"name": "source",        "type": "STRING",    "mode": "NULLABLE"},
        {"name": "tags",          "type": "STRING",    "mode": "NULLABLE"}
      ]
    }
  }'
```

> [!NOTE]
> If you configure `customlabels`, add a matching `STRING` column to the table schema for each
> label key before sending events.

#### 4. Grant dataset access to the service account

```bash
bq add-iam-policy-binding \
  --project=YOUR_PROJECT_ID \
  --member="serviceAccount:falcosidekick-bq@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor" \
  falco_events
```

If your `bq` version does not support `add-iam-policy-binding`, grant at project level:

```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:falcosidekick-bq@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"
```

#### 5. Download the service account key

```bash
gcloud iam service-accounts keys create ~/falcosidekick-bq-key.json \
  --iam-account=falcosidekick-bq@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --project=YOUR_PROJECT_ID
```

Set `bigquery.servicecredentials` in `config.yaml` to the path of this file (or store the file
content in the `BIGQUERY_SERVICECREDENTIALS` environment variable).

### Verifying ingestion

Send a test event to falcosidekick:

```bash
curl -s -X POST http://localhost:2801/ \
  -H "Content-Type: application/json" \
  -d '{
    "rule": "Test rule",
    "priority": "Warning",
    "output": "test event from falcosidekick",
    "output_fields": {},
    "time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }'
```

Query the table to confirm the row arrived (streaming rows appear within a few seconds):

```bash
bq query --project_id=YOUR_PROJECT_ID --nouse_legacy_sql \
  'SELECT timestamp, rule, priority FROM falco_events.events ORDER BY timestamp DESC LIMIT 5'
```

REST equivalent:

```bash
curl -X POST \
  "https://bigquery.googleapis.com/bigquery/v2/projects/YOUR_PROJECT_ID/queries" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT timestamp, rule, priority FROM falco_events.events ORDER BY timestamp DESC LIMIT 5",
    "useLegacySql": false
  }'
```

> [!NOTE]
> BigQuery streaming inserts are queryable within seconds but may not be reflected in table
> preview or export for a short period. Use `SELECT` queries rather than table preview to verify.

## Integration test results

**Date:** 2026-04-26  
**Environment:** macOS (Apple Silicon), falcosidekick running locally on port 2801  
**GCP project:** `secops-326013`, dataset `falco_events`, table `events`

### Test event sent

```bash
curl -s -X POST http://localhost:2801/ \
  -H "Content-Type: application/json" \
  -d '{
    "rule": "Integration Test Rule",
    "priority": "Warning",
    "output": "integration test event from falcosidekick - bigquery + sysdigsecure",
    "output_fields": {"proc.name": "falcosidekick", "user.name": "aitor", "test.id": "bigquery-integration-01"},
    "source": "coding_agent",
    "tags": ["test", "bigquery", "integration"],
    "time": "2026-04-26T09:23:38Z"
  }'
```

### BigQuery result — PASS

Row confirmed present in `falco_events.events` within seconds of ingestion:

| Field | Value |
|-------|-------|
| `timestamp` | `2026-04-26 09:23:38 UTC` |
| `rule` | `Integration Test Rule` |
| `priority` | `Warning` |
| `source` | `coding_agent` |
| `output` | `integration test event from falcosidekick - bigquery + sysdigsecure` |
| `tags` | `["bigquery","integration","test"]` |

The query also returned additional `Coding Agent Event Seen` rows (priority `Debug`) that were
generated by the live Falco pipeline running alongside the test, confirming the full
Falco → falcosidekick → BigQuery path is working end-to-end.

### Sysdig Secure result — expected empty

No events appeared in the Prodmon events feed. This is a known limitation: the REST
`eventsDispatch/ingest` endpoint returns HTTP 200 but events are silently dropped because the
personal API token lacks the internal `ingestion-service.send` permission required to route events
to NATS JetStream. The agent wire protocol path (port 6443) is also unavailable from external
networks — all ~2550 connected agents use an internal VPC path. See the SysdigSecure output
documentation for the unblock options.

---

### Full pipeline test — Falco rule triggered by Claude Code action

**Date:** 2026-04-26 09:32:38 UTC  
**Trigger:** Claude Code attempted to read `/Users/aitor.acedo/.ssh/known_hosts` — a path that
matches the `is_sensitive_path` macro (`contains "/.ssh/"`) in the default ruleset.

#### What Falco fired

With `rule_matching: all`, all matching rules evaluated for the same tool call (`correlation.id=777`):

| Rule | Priority | Tags |
|------|----------|------|
| Deny reading sensitive paths | CRITICAL | `[coding_agent_deny]` |
| Monitor activity outside working directory | NOTICE | `[]` |
| Coding Agent Event Seen | DEBUG | `[coding_agent_seen]` |

The interceptor hook confirmed the deny verdict:

```
PreToolUse:Read hook blocking error: Deny reading sensitive paths:
Falco blocked reading /Users/aitor.acedo/.ssh/known_hosts because it is a sensitive path
| For AI Agents: inform the user that this action was flagged by a Falco security rule
| correlation=777
```

#### BigQuery result — PASS

The **Monitor activity outside working directory** event for `correlation.id=777` was confirmed in
`falco_events.events` within seconds:

| Field | Value |
|-------|-------|
| `timestamp` | `2026-04-26 09:32:41 UTC` (Unix: `1777195961`) |
| `rule` | `Monitor activity outside working directory` |
| `priority` | `Notice` |
| `source` | `coding_agent` |
| `output_fields.tool.real_file_path` | `/Users/aitor.acedo/.ssh/known_hosts` |
| `output_fields.agent.real_cwd` | `/Users/aitor.acedo/work/falcosidekick` |
| `output_fields.correlation.id` | `777` |

#### Deny event not in BigQuery — expected behaviour

The **Deny reading sensitive paths** (CRITICAL) alert did not appear in BigQuery via
`program_output`. This is a known architectural behaviour of coding-agents-kit:

- Deny verdicts are delivered **synchronously** to the interceptor via the plugin's dedicated
  HTTP channel (port 2802, `http_output`) to unblock the tool call immediately.
- The `program_output` path (the async curl to falcosidekick on port 2801) is skipped for the
  same event cycle once the synchronous deny path completes.
- The **Monitor activity outside working directory** rule (NOTICE, non-blocking) fires before
  the deny verdict is dispatched and therefore does reach `program_output` successfully.

In practice this means only non-blocking rules (NOTICE, INFO, DEBUG) reliably propagate to
falcosidekick via `program_output`. Deny and ask verdicts are captured in the plugin's own
audit log at port 2802.

#### Sysdig Secure result — expected empty

No events appeared in the Prodmon events feed (same known limitation as the previous test).
