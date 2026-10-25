// Package protocol is the wire protocol between ezgh-fleets-agent, the EZGH Fleets
// gateway and the clients (console and CLI) that open shell sessions through it.
//
// Agent control connections (/agent/v1/connect) carry JSON text frames whose "t" field names
// the message. Session connections carry binary data frames (EncodeData) and JSON controls,
// relayed unchanged between client and agent. Instructions that make the agent start anything
// are signed (SignInstruction) by keys published in a key list signed by a root in Roots.
package protocol

import "time"

const (
	AgentSubprotocol   = "ezgh.fleets.agent.v1"
	SessionSubprotocol = "ezgh.fleets.session.v1"
	TicketPrefix       = "ticket."
	HeaderNode         = "EZGH-Node"              // nod_ slug on agent upgrades
	ConnectContext     = "ezgh-fleets-connect-v1" // signed: ConnectContext+"\n"+nodeID+"\n"+nonce
	DataContext        = "ezgh-fleets-data-v1"    // signed: DataContext+"\n"+nodeID+"\n"+sessionID+"\n"+nonce
	MaxFrame           = 1 << 20
	ResumeBuffer       = 256 << 10
)

// Message types, the "t" field.
const (
	TypeChallenge         = "challenge"
	TypeHello             = "hello"
	TypeWelcome           = "welcome"
	TypeInstruction       = "instruction"
	TypeCancel            = "cancel"
	TypeSessionClosed     = "sessionClosed"
	TypeReconnect         = "reconnect"
	TypeRekey             = "rekey"
	TypeInvocationStarted = "invocationStarted"
	TypeInvocationResult  = "invocationResult"
	TypeRefused           = "refused"
	TypeSessionEnded      = "sessionEnded"

	TypeResize = "resize"
	TypeAck    = "ack"
	TypeResume = "resume"
	TypeExit   = "exit"
	TypeStatus = "status"
)

// Instruction types.
const (
	TypeOpenSession   = "openSession"
	TypeResumeSession = "resumeSession"
	TypeRunInvocation = "runInvocation"
)

// ConnectMessage is what the agent signs with its node key to answer a control challenge.
func ConnectMessage(nodeID, nonce string) []byte {
	return []byte(ConnectContext + "\n" + nodeID + "\n" + nonce)
}

// DataMessage is what the agent signs with its node key to open a session's data connection.
func DataMessage(nodeID, sessionID, nonce string) []byte {
	return []byte(DataContext + "\n" + nodeID + "\n" + sessionID + "\n" + nonce)
}

// Control messages on /agent/v1/connect.

type Challenge struct {
	T     string `json:"t"`
	Nonce string `json:"nonce"` // base64url, 32 bytes
}

// Hello answers a Challenge, agent → gateway. Signature is base64url Ed25519 over
// ConnectMessage (or DataMessage on a data connection).
type Hello struct {
	T            string    `json:"t"`
	Signature    string    `json:"signature"`
	AgentVersion string    `json:"agentVersion"`
	Time         time.Time `json:"time"`
}

type Welcome struct {
	T          string        `json:"t"`
	KeyList    SignedKeyList `json:"keyList"`
	ServerTime time.Time     `json:"serverTime"`
}

type Deliver struct {
	T           string            `json:"t"`
	Instruction SignedInstruction `json:"instruction"`
}

// Cancel stops a running invocation. It's unsigned: it can only stop things.
type Cancel struct {
	T     string `json:"t"`
	RunID string `json:"runId"`
}

type SessionClosed struct {
	T         string `json:"t"`
	SessionID string `json:"sessionId"`
	Reason    string `json:"reason"`
}

// Reconnect asks the agent to reconnect elsewhere; also sent as close code 4012.
type Reconnect struct {
	T string `json:"t"`
}

// Rekey hands the gateway a fresh API key, agent → gateway.
type Rekey struct {
	T      string `json:"t"`
	APIKey string `json:"apiKey"`
}

type InvocationStarted struct {
	T         string    `json:"t"`
	RunID     string    `json:"runId"`
	StartedAt time.Time `json:"startedAt"`
}

type InvocationResult struct {
	T         string     `json:"t"`
	RunID     string     `json:"runId"`
	Status    string     `json:"status"`           // succeeded|failed|timed_out|cancelled
	Reason    string     `json:"reason,omitempty"` // e.g. agent_restarted, osUser_not_found
	ExitCode  *int       `json:"exitCode,omitempty"`
	StartedAt *time.Time `json:"startedAt,omitempty"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
}

// Refused reports an instruction the agent wouldn't act on.
type Refused struct {
	T      string `json:"t"`
	ID     string `json:"id"`
	Reason string `json:"reason"` // expired|wrong_node|replayed|bad_signature|unknown_key
}

// SessionEnded reports that the agent ended a PTY.
type SessionEnded struct {
	T         string `json:"t"`
	SessionID string `json:"sessionId"`
	Reason    string `json:"reason"` // exited|client_gone|osUser_not_found
}

// Signed instructions.

// SignedInstruction carries an Instruction as the exact bytes that were signed.
type SignedInstruction struct {
	V       int    `json:"v"`
	Kid     string `json:"kid"`
	Payload string `json:"payload"` // base64url JSON bytes as signed
	Sig     string `json:"sig"`     // base64url Ed25519
}

type Instruction struct {
	Type           string            `json:"type"`   // openSession | resumeSession | runInvocation
	NodeID         string            `json:"nodeId"` // node UUID
	ID             string            `json:"id"`     // session or run UUID
	OSUser         *string           `json:"osUser,omitempty"`
	Person         *Person           `json:"person,omitempty"`
	EzghUserSudo   bool              `json:"ezghUserSudo,omitempty"`
	Command        *string           `json:"command,omitempty"`
	Script         *Script           `json:"script,omitempty"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	TimeoutSeconds int               `json:"timeoutSeconds,omitempty"`
	IssuedAt       time.Time         `json:"issuedAt"`
	ExpiresAt      time.Time         `json:"expiresAt"`
}

type Person struct {
	Type     string `json:"type"` // user|ssoUser
	ID       string `json:"id"`
	BaseName string `json:"baseName"`
}

type Script struct {
	Shell  string `json:"shell"`
	Body   string `json:"body"`
	SHA256 string `json:"sha256"`
}

// SignedKeyList carries the instruction public keys, signed by a root in Roots.
// Payload: base64url JSON {keys:[{kid, publicKey, notAfter}], issuedAt}.
type SignedKeyList struct {
	V       int    `json:"v"`
	RootKid string `json:"rootKid"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// PublicKey is one instruction-signing key in a key list.
type PublicKey struct {
	Kid       string
	PublicKey []byte // raw Ed25519, base64url on the wire
	NotAfter  time.Time
}

// Session framing, client ↔ agent, relayed unchanged.

type Resize struct {
	T    string `json:"t"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// Ack, both ways, every 1 s or 64 KiB: the peer has every byte before Offset.
type Ack struct {
	T      string `json:"t"`
	Offset uint64 `json:"offset"`
}

// Resume is the first message after every (re)connect, both ways: send from Offset.
type Resume struct {
	T      string `json:"t"`
	Offset uint64 `json:"offset"`
}

type Exit struct {
	T    string `json:"t"`
	Code int    `json:"code"`
}

// Status, gateway → client: reconnecting|connected.
type Status struct {
	T     string `json:"t"`
	State string `json:"state"`
}
