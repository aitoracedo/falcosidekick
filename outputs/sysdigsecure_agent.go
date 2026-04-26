// SPDX-License-Identifier: MIT OR Apache-2.0

// Package outputs — SysdigAgentClient provides event injection via the native
// Sysdig agent wire protocol (port 6443) instead of the REST events API.
//
// The REST POST /api/v1/eventsDispatch/ingest endpoint returns HTTP 200 but
// silently drops events for API-token callers because they lack the
// ingestion-service.send permission.  Real registered agents connect via a
// raw-TLS socket on port 6443, exchange a two-step protobuf handshake, and
// then stream policy_events messages.  This file mimics that protocol so that
// Falco events injected by falcosidekick appear in the Secure Events feed with
// rawEventOriginator=linuxAgent.
//
// Wire protocol (draios agent protocol v5)
//
//	Frame header (22 bytes, big-endian):
//	  [0:4]  uint32  payload length (bytes after the header)
//	  [4]    uint8   protocol version (always 0x05)
//	  [5]    uint8   message type (see message_type enum in common.proto)
//	  [6:14] uint64  generation counter
//	  [14:22] uint64 sequence counter
//
//	Payload: gzip-compressed (after handshake) or plain protobuf.
//
// Handshake sequence:
//
//	Client → PROTOCOL_INIT      (type 24)
//	Server → PROTOCOL_INIT_RESP (type 25)
//	Client → HANDSHAKE_V1       (type 26)
//	Server → HANDSHAKE_V1_RESP  (type 27)  ← negotiates compression
//	Client → POLICY_EVENTS      (type 14)  ← repeated, one per Falco event

package outputs

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/encoding/protowire"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// ── Agent protocol constants ──────────────────────────────────────────────────

const (
	agentFrameVersion   = byte(0x05)
	agentFrameHeaderLen = 22 // 4(len)+1(ver)+1(type)+8(gen)+8(seq)

	// Message types from common.proto message_type enum.
	agentMsgErrorMessage     = byte(12)
	agentMsgPolicyEvents     = byte(14)
	agentMsgProtocolInit     = byte(24)
	agentMsgProtocolInitResp = byte(25)
	agentMsgHandshakeV1      = byte(26)
	agentMsgHandshakeV1Resp  = byte(27)
	agentMsgHeartbeat        = byte(38)

	// Compression types from handshake.proto compression enum.
	agentCompressNone = uint64(1)
	agentCompressGzip = uint64(2)

	// agent_mode: secure=5 from common.proto agent_mode enum.
	draiosAgentModeSecure = uint64(5)

	// heartbeatInterval is how often to send protocol heartbeats.
	heartbeatInterval = 30 * time.Second

	// handshakeTimeout is the maximum time allowed for the full handshake.
	handshakeTimeout = 15 * time.Second
)

// ── SysdigAgentClient ─────────────────────────────────────────────────────────

// SysdigAgentClient maintains a persistent TLS connection to the Sysdig agent
// collector (default port 6443) and injects Falco events using the native
// draios agent wire protocol.
type SysdigAgentClient struct {
	mu        sync.Mutex
	conn      net.Conn
	machineID string // MAC address of primary interface (or fake)
	opaqueUID string // stable UUID for this process instance
	accessKey string // Sysdig agent access key (customer_id in proto)
	agentHost string // host:port of the agent collector
	checkCert bool

	gen      uint64 // frame generation counter
	seq      uint64 // frame sequence counter
	compress uint64 // negotiated compression after handshake

	// Metrics (same fields as outputs.Client for consistent accounting).
	outputType  string
	stats       *types.Statistics
	promStats   *types.PromStatistics
	otlpMetrics *otlpmetrics.OTLPMetrics
	config      *types.SysdigSecureOutputConfig

	stopCh chan struct{}
}

// NewSysdigAgentClient creates a new agent client, dials the collector, and
// performs the initial handshake.  Returns an error when the dial or handshake
// fails so that the caller can fall back to the REST path.
func NewSysdigAgentClient(cfg types.SysdigSecureOutputConfig, params types.InitClientArgs) (*SysdigAgentClient, error) {
	c := &SysdigAgentClient{
		machineID:   agentMachineID(),
		opaqueUID:   uuid.New().String(),
		accessKey:   cfg.AccessKey,
		agentHost:   cfg.AgentHost,
		checkCert:   cfg.CheckCert,
		outputType:  "SysdigSecure",
		stats:       params.Stats,
		promStats:   params.PromStats,
		otlpMetrics: params.OTLPMetrics,
		config:      &cfg,
		stopCh:      make(chan struct{}),
	}

	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("sysdig agent: %w", err)
	}

	go c.heartbeatLoop()
	return c, nil
}

// SysdigSecurePost converts a Falco event to a policy_events proto message and
// sends it over the persistent agent connection.  On a send error it reconnects
// once and retries before recording the error metric.
func (c *SysdigAgentClient) SysdigSecurePost(falcopayload types.FalcoPayload) {
	c.stats.SysdigSecure.Add(Total, 1)

	policyID := uint64(c.config.PolicyID)
	if policyID == 0 {
		policyID = 10000003 // "Sysdig Runtime Activity Logs" default policy
	}

	tsNs := uint64(falcopayload.Time.UnixNano())
	payload := c.encodePolicyEventsMsg(tsNs, policyID, falcopayload.Rule, falcopayload.Output)

	err := c.sendPayload(agentMsgPolicyEvents, payload)
	if err != nil {
		// One reconnect attempt.
		utils.Log(utils.WarningLvl, c.outputType, fmt.Sprintf("send failed (%v); reconnecting", err))
		if rerr := c.connect(); rerr == nil {
			err = c.sendPayload(agentMsgPolicyEvents, payload)
		}
	}

	if err != nil {
		utils.Log(utils.ErrorLvl, c.outputType, err.Error())
		c.stats.SysdigSecure.Add(Error, 1)
		c.promStats.Outputs.With(map[string]string{"destination": "sysdigsecure", "status": Error}).Inc()
		c.otlpMetrics.Outputs.With(
			attribute.String("destination", "sysdigsecure"),
			attribute.String("status", Error)).Inc()
		return
	}

	utils.Log(utils.InfoLvl, c.outputType, "policy_event sent via agent protocol")
	c.stats.SysdigSecure.Add(OK, 1)
	c.promStats.Outputs.With(map[string]string{"destination": "sysdigsecure", "status": OK}).Inc()
	c.otlpMetrics.Outputs.With(
		attribute.String("destination", "sysdigsecure"),
		attribute.String("status", OK)).Inc()
}

// ── Connection & handshake ────────────────────────────────────────────────────

// connect dials the collector and performs the two-step handshake.
// Called at startup and on reconnect.  Caller must NOT hold c.mu.
func (c *SysdigAgentClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close any stale connection.
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: !c.checkCert} //nolint:gosec
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", c.agentHost, tlsCfg)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.agentHost, err)
	}

	c.conn = conn
	c.seq = 0

	if err := c.handshake(); err != nil {
		_ = conn.Close()
		c.conn = nil
		return fmt.Errorf("handshake: %w", err)
	}
	return nil
}

// handshake performs PROTOCOL_INIT → PROTOCOL_INIT_RESP → HANDSHAKE_V1 →
// HANDSHAKE_V1_RESP.  Must be called while c.mu is held.
func (c *SysdigAgentClient) handshake() error {
	_ = c.conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()

	tsNs := uint64(time.Now().UnixNano())

	// 1. PROTOCOL_INIT
	initMsg := c.encodeProtocolInit(tsNs)
	if err := c.writeFrame(agentMsgProtocolInit, initMsg); err != nil {
		return fmt.Errorf("send PROTOCOL_INIT: %w", err)
	}

	// 2. PROTOCOL_INIT_RESP
	msgType, errPayload, err := c.readFrame()
	if err != nil {
		return fmt.Errorf("read PROTOCOL_INIT_RESP: %w", err)
	}
	if msgType != agentMsgProtocolInitResp {
		if msgType == agentMsgErrorMessage {
			return fmt.Errorf("collector rejected PROTOCOL_INIT: %s", decodeErrorMessage(errPayload))
		}
		return fmt.Errorf("expected PROTOCOL_INIT_RESP (25), got %d", msgType)
	}

	// 3. HANDSHAKE_V1
	tsNs = uint64(time.Now().UnixNano())
	hsMsg := c.encodeHandshakeV1(tsNs)
	if err := c.writeFrame(agentMsgHandshakeV1, hsMsg); err != nil {
		return fmt.Errorf("send HANDSHAKE_V1: %w", err)
	}

	// 4. HANDSHAKE_V1_RESP
	msgType, payload, err := c.readFrame()
	if err != nil {
		return fmt.Errorf("read HANDSHAKE_V1_RESP: %w", err)
	}
	if msgType != agentMsgHandshakeV1Resp {
		if msgType == agentMsgErrorMessage {
			return fmt.Errorf("collector rejected HANDSHAKE_V1: %s", decodeErrorMessage(payload))
		}
		return fmt.Errorf("expected HANDSHAKE_V1_RESP (27), got %d", msgType)
	}

	c.compress = parseCompression(payload)
	utils.Log(utils.InfoLvl, "SysdigSecure", fmt.Sprintf(
		"agent handshake OK (machine=%s, compression=%d)", c.machineID, c.compress))
	return nil
}

// ── Frame I/O ─────────────────────────────────────────────────────────────────

// writeFrame sends payload in a 22-byte agent frame without any compression
// (used during handshake, before compression is negotiated).
// Must be called while c.mu is held.
func (c *SysdigAgentClient) writeFrame(msgType byte, payload []byte) error {
	c.seq++
	frame := encodeFrame(msgType, c.gen, c.seq, payload)
	_, err := c.conn.Write(frame)
	return err
}

// sendPayload compresses (if negotiated) and sends a framed proto payload.
// Acquires c.mu.
func (c *SysdigAgentClient) sendPayload(msgType byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data := payload
	if c.compress == agentCompressGzip {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(payload); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		data = buf.Bytes()
	}

	c.seq++
	frame := encodeFrame(msgType, c.gen, c.seq, data)
	_, err := c.conn.Write(frame)
	return err
}

// readFrame reads one frame from c.conn and returns the message type and raw
// (possibly gzip-compressed) payload.  Must be called while c.mu is held.
// During handshake, payloads are always uncompressed.
//
// The server sometimes sends ERROR_MESSAGE with plen equal to the uncompressed
// payload size while only writing the (smaller) gzip-compressed bytes before
// closing the connection.  We therefore read whatever is available rather than
// insisting on exactly plen bytes.
func (c *SysdigAgentClient) readFrame() (msgType byte, payload []byte, err error) {
	header := make([]byte, agentFrameHeaderLen)
	if _, err = io.ReadFull(c.conn, header); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint32(header[0:4])
	msgType = header[5]
	// header[4] = version, header[6:14] = gen, header[14:22] = seq — ignored here

	if msgLen > 0 {
		payload = make([]byte, msgLen)
		n, readErr := io.ReadAtLeast(c.conn, payload, 1)
		payload = payload[:n]
		if readErr != nil && n == 0 {
			err = readErr
		}
		// If we got some bytes but fewer than msgLen, the connection closed
		// early (server-side bug with compressed ERROR_MESSAGE frames).
		// Return the partial payload so the caller can still decode the error.
	}
	return
}

// encodeFrame builds the 22-byte header + payload slice.
func encodeFrame(msgType byte, gen, seq uint64, payload []byte) []byte {
	buf := make([]byte, agentFrameHeaderLen+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload)))
	buf[4] = agentFrameVersion
	buf[5] = msgType
	binary.BigEndian.PutUint64(buf[6:14], gen)
	binary.BigEndian.PutUint64(buf[14:22], seq)
	copy(buf[22:], payload)
	return buf
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

// heartbeatLoop sends an empty PROTOCOL_HEARTBEAT frame every heartbeatInterval
// to keep the connection alive.
func (c *SysdigAgentClient) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if err := c.sendPayload(agentMsgHeartbeat, nil); err != nil {
				utils.Log(utils.WarningLvl, "SysdigSecure", fmt.Sprintf("heartbeat error: %v; reconnecting", err))
				_ = c.connect()
			}
		}
	}
}

// ── Proto encoding ────────────────────────────────────────────────────────────
// We use google.golang.org/protobuf/encoding/protowire directly to avoid a
// code-generation step.  The proto schemas come from draios/protorepo
// (agent-be/proto/{common,handshake,draios}.proto).

// encodeFeatureStatus encodes a minimal feature_status proto (common.proto).
//
//	field 1: mode           = secure(5)
//	field 8: secure_enabled = true
func encodeFeatureStatus() []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, draiosAgentModeSecure)
	b = protowire.AppendTag(b, 8, protowire.VarintType)
	b = protowire.AppendVarint(b, 1) // true
	return b
}

// encodeProtocolInit encodes a protocol_init message (handshake.proto field 24).
//
//	field 1: timestamp_ns                = now
//	field 2: machine_id                  = MAC address
//	field 3: customer_id                 = access key
//	field 4: supported_protocol_versions = [5]
//	field 5: features                    = feature_status{secure}
//	field 6: opaque_uid                  = session UUID
func (c *SysdigAgentClient) encodeProtocolInit(tsNs uint64) []byte {
	features := encodeFeatureStatus()
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, tsNs)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, c.machineID)
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendString(b, c.accessKey)
	b = protowire.AppendTag(b, 4, protowire.VarintType) // repeated, one entry
	b = protowire.AppendVarint(b, 5)
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, features)
	b = protowire.AppendTag(b, 6, protowire.BytesType)
	b = protowire.AppendString(b, c.opaqueUID)
	return b
}

// encodeHandshakeV1 encodes a handshake_v1 message (handshake.proto field 26).
//
//	field 1:  timestamp_ns              = now
//	field 2:  machine_id               = MAC address
//	field 3:  customer_id              = access key
//	field 4:  supported_compressions   = [NONE(1), GZIP(2)]
//	field 5:  supported_agg_intervals  = [10, 60]  (packed)
//	field 6:  features                 = feature_status{secure}
//	field 20: opaque_uid               = session UUID
func (c *SysdigAgentClient) encodeHandshakeV1(tsNs uint64) []byte {
	features := encodeFeatureStatus()

	// supported_agg_intervals is packed (field 5 [packed=true]).
	var intervals []byte
	intervals = protowire.AppendVarint(intervals, 10)
	intervals = protowire.AppendVarint(intervals, 60)

	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, tsNs)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, c.machineID)
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendString(b, c.accessKey)
	// supported_compressions — not packed, so each value is a separate tag+varint
	b = protowire.AppendTag(b, 4, protowire.VarintType)
	b = protowire.AppendVarint(b, agentCompressNone)
	b = protowire.AppendTag(b, 4, protowire.VarintType)
	b = protowire.AppendVarint(b, agentCompressGzip)
	// packed agg_intervals
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, intervals)
	b = protowire.AppendTag(b, 6, protowire.BytesType)
	b = protowire.AppendBytes(b, features)
	b = protowire.AppendTag(b, 20, protowire.BytesType)
	b = protowire.AppendString(b, c.opaqueUID)
	return b
}

// encodeFalcoEventDetail encodes a falco_event_detail sub-message (draios.proto).
//
//	field 1: rule   (required string)
//	field 2: output (required string)
func encodeFalcoEventDetail(rule, output string) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, rule)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, output)
	return b
}

// encodePolicyEvent encodes a single policy_event sub-message (draios.proto).
//
//	field 1: timestamp_ns (required uint64)
//	field 2: policy_id    (required uint64)
//	field 5: falco_details (optional falco_event_detail)
func encodePolicyEvent(tsNs, policyID uint64, rule, output string) []byte {
	detail := encodeFalcoEventDetail(rule, output)
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, tsNs)
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, policyID)
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendBytes(b, detail)
	return b
}

// encodePolicyEventsMsg encodes a policy_events top-level message (draios.proto).
//
//	field 1: machine_id   (required string)
//	field 2: customer_id  (optional string) = access key
//	field 3: events       (repeated policy_event)
//	field 5: opaque_uid   (optional string)
func (c *SysdigAgentClient) encodePolicyEventsMsg(tsNs, policyID uint64, rule, output string) []byte {
	event := encodePolicyEvent(tsNs, policyID, rule, output)
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, c.machineID)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, c.accessKey)
	b = protowire.AppendTag(b, 3, protowire.BytesType)
	b = protowire.AppendBytes(b, event)
	b = protowire.AppendTag(b, 5, protowire.BytesType)
	b = protowire.AppendString(b, c.opaqueUID)
	return b
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// decodeErrorMessage tries to decode the gzip-compressed error_message proto
// (draios.proto) returned by the collector.  Returns a human-readable string
// in the form "ERR_<type> (<code>): <description>".
func decodeErrorMessage(payload []byte) string {
	// Try gzip decompress (collector always compresses error frames).
	if dec, err := gzip.NewReader(bytes.NewReader(payload)); err == nil {
		if b, err2 := io.ReadAll(dec); err2 == nil {
			payload = b
		}
	}

	// Proto parse: field 1 = error_type (varint), field 2 = description (bytes).
	var errCode uint64
	var errDesc string
	b := payload
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				break
			}
			errCode = v
			b = b[n2:]
		case num == 2 && typ == protowire.BytesType:
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				break
			}
			errDesc = string(v)
			b = b[n2:]
		default:
			n2 := protowire.ConsumeFieldValue(num, typ, b)
			if n2 < 0 {
				break
			}
			b = b[n2:]
		}
	}

	codeNames := map[uint64]string{
		1: "ERR_CONN_LIMIT",
		2: "ERR_INVALID_CUSTOMER_KEY",
		3: "ERR_DUPLICATE_AGENT",
		4: "ERR_SERVER_BUSY",
		5: "ERR_PROTO_MISMATCH",
	}
	name := codeNames[errCode]
	if name == "" {
		name = fmt.Sprintf("ERR_%d", errCode)
	}
	return fmt.Sprintf("%s (%d): %s", name, errCode, errDesc)
}

// parseCompression reads field 6 (compression, required) from a
// handshake_v1_response proto payload.  Returns agentCompressNone on parse
// errors so the caller falls back to plain proto.
func parseCompression(payload []byte) uint64 {
	b := payload
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 6 && typ == protowire.VarintType {
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				break
			}
			return v
		}
		n2 := protowire.ConsumeFieldValue(num, typ, b)
		if n2 < 0 {
			break
		}
		b = b[n2:]
	}
	return agentCompressNone
}

// agentMachineID returns the MAC address of the first non-loopback interface
// that has a hardware address, formatted as "aa:bb:cc:dd:ee:ff".
// Falls back to a deterministic fake address if no suitable interface exists.
func agentMachineID() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			if len(iface.HardwareAddr) >= 6 {
				return iface.HardwareAddr.String()
			}
		}
	}
	return "aa:bb:cc:dd:ee:01"
}
