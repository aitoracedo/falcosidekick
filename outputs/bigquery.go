// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

const bigqueryScope = "https://www.googleapis.com/auth/bigquery.insertdata"

// BigQueryClient streams Falco events into a BigQuery table via the
// tabledata.insertAll REST API.
type BigQueryClient struct {
	outputType  string
	stats       *types.Statistics
	promStats   *types.PromStatistics
	otlpMetrics *otlpmetrics.OTLPMetrics
	httpClient  *http.Client
	insertURL   string
	customLabels map[string]string
}

type bigqueryRow struct {
	InsertID string                 `json:"insertId,omitempty"`
	JSON     map[string]interface{} `json:"json"`
}

type bigqueryInsertRequest struct {
	Rows []bigqueryRow `json:"rows"`
}

// NewBigQueryClient creates a BigQueryClient authenticated via the provided
// service account credentials. ServiceCredentials may be either a file path
// to a JSON key file or the raw JSON content of the key.
func NewBigQueryClient(params types.InitClientArgs) (*BigQueryClient, error) {
	cfg := params.Config.BigQuery

	if cfg.ServiceCredentials == "" {
		return nil, fmt.Errorf("BigQuery.ServiceCredentials is required")
	}
	if cfg.ProjectID == "" || cfg.DatasetID == "" || cfg.TableID == "" {
		return nil, fmt.Errorf("BigQuery.ProjectID, DatasetID, and TableID are all required")
	}

	credBytes, err := loadCredentials(cfg.ServiceCredentials)
	if err != nil {
		return nil, fmt.Errorf("BigQuery credentials: %w", err)
	}

	creds, err := google.CredentialsFromJSON(context.Background(), credBytes, bigqueryScope)
	if err != nil {
		return nil, fmt.Errorf("BigQuery: loading GCP credentials: %w", err)
	}

	serviceURL := strings.TrimRight(cfg.ServiceURL, "/")
	insertURL := fmt.Sprintf(
		"%s/bigquery/v2/projects/%s/datasets/%s/tables/%s/insertAll",
		serviceURL, cfg.ProjectID, cfg.DatasetID, cfg.TableID,
	)

	labels := make(map[string]string)
	for k, v := range cfg.CustomLabels {
		labels[k] = v
	}

	return &BigQueryClient{
		outputType:   "BigQuery",
		stats:        params.Stats,
		promStats:    params.PromStats,
		otlpMetrics:  params.OTLPMetrics,
		httpClient:   oauth2.NewClient(context.Background(), creds.TokenSource),
		insertURL:    insertURL,
		customLabels: labels,
	}, nil
}

// loadCredentials returns the raw JSON bytes of a service account key.
// If s starts with '{' it is treated as inline JSON; otherwise it is read
// from the file path given by s.
func loadCredentials(s string) ([]byte, error) {
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		return []byte(s), nil
	}
	b, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("reading credentials file %q: %w", s, err)
	}
	return b, nil
}

// BigQueryPost sends a Falco event as a streaming insert row to BigQuery.
func (c *BigQueryClient) BigQueryPost(falcopayload types.FalcoPayload) {
	c.stats.BigQuery.Add(Total, 1)

	outputFieldsJSON, err := json.Marshal(falcopayload.OutputFields)
	if err != nil {
		c.recordError(fmt.Errorf("marshal output_fields: %w", err))
		return
	}
	tagsJSON, err := json.Marshal(falcopayload.Tags)
	if err != nil {
		c.recordError(fmt.Errorf("marshal tags: %w", err))
		return
	}

	row := bigqueryRow{
		InsertID: fmt.Sprintf("%d", falcopayload.Time.UnixNano()),
		JSON: map[string]interface{}{
			"timestamp":     falcopayload.Time.UTC().Format(time.RFC3339Nano),
			"rule":          falcopayload.Rule,
			"priority":      falcopayload.Priority.String(),
			"output":        falcopayload.Output,
			"output_fields": string(outputFieldsJSON),
			"source":        falcopayload.Source,
			"tags":          string(tagsJSON),
		},
	}
	for k, v := range c.customLabels {
		row.JSON[k] = v
	}

	body, err := json.Marshal(bigqueryInsertRequest{Rows: []bigqueryRow{row}})
	if err != nil {
		c.recordError(fmt.Errorf("marshal: %w", err))
		return
	}

	resp, err := c.httpClient.Post(c.insertURL, "application/json", bytes.NewReader(body))
	if err != nil {
		c.recordError(fmt.Errorf("HTTP POST: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.recordError(fmt.Errorf("unexpected status %d", resp.StatusCode))
		return
	}

	// The insertAll response may carry per-row insert errors even on HTTP 200.
	var result struct {
		InsertErrors []struct {
			Index  int `json:"index"`
			Errors []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"insertErrors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && len(result.InsertErrors) > 0 {
		first := result.InsertErrors[0].Errors
		msg := "insert error"
		if len(first) > 0 {
			msg = fmt.Sprintf("%s: %s", first[0].Reason, first[0].Message)
		}
		c.recordError(fmt.Errorf(msg))
		return
	}

	c.stats.BigQuery.Add(OK, 1)
	c.promStats.Outputs.With(map[string]string{"destination": "bigquery", "status": OK}).Inc()
	c.otlpMetrics.Outputs.With(attribute.String("destination", "bigquery"), attribute.String("status", OK)).Inc()
}

func (c *BigQueryClient) recordError(err error) {
	utils.Log(utils.ErrorLvl, c.outputType, err.Error())
	c.stats.BigQuery.Add(Error, 1)
	c.promStats.Outputs.With(map[string]string{"destination": "bigquery", "status": Error}).Inc()
	c.otlpMetrics.Outputs.With(attribute.String("destination", "bigquery"), attribute.String("status", Error)).Inc()
}
