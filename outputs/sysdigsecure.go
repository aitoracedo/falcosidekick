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
	Labels map[string]string    `json:"labels"`
	Events []sysdigSecureEvent  `json:"events"`
}

func newSysdigSecurePayload(falcopayload types.FalcoPayload, customLabels map[string]string) sysdigSecureEventCollection {
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

	return sysdigSecureEventCollection{
		Labels: labels,
		Events: []sysdigSecureEvent{event},
	}
}

// SysdigSecurePost posts a Falco event to the Sysdig Secure Events API
func (c *Client) SysdigSecurePost(falcopayload types.FalcoPayload) {
	c.Stats.SysdigSecure.Add(Total, 1)

	token := c.Config.SysdigSecure.APIToken
	account := c.Config.SysdigSecure.CloudAccount
	region := c.Config.SysdigSecure.CloudRegion
	provider := c.Config.SysdigSecure.CloudProvider

	optfn := func(req *http.Request) {
		req.Header.Set(AuthorizationHeaderKey, Bearer+" "+token)
		if account != "" {
			req.Header.Set("X-Sysdig-Cloud-Account", account)
		}
		if region != "" {
			req.Header.Set("X-Sysdig-Cloud-Region", region)
		}
		if provider != "" {
			req.Header.Set("X-Sysdig-Cloud-Provider", provider)
		}
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
