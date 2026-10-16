package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Stream type bytes, written first by whoever opens a stream.
const (
	StreamControl byte = 0x01
	StreamProxy   byte = 0x02
)

// ProtocolVersion is the control protocol version.
const ProtocolVersion = 1

// Connection close codes. Each maps to a user-facing explanation.
const (
	CodeNormal          quic.ApplicationErrorCode = 0x00
	CodeBadSecret       quic.ApplicationErrorCode = 0x10
	CodeExpired         quic.ApplicationErrorCode = 0x11
	CodeDenied          quic.ApplicationErrorCode = 0x12
	CodeFull            quic.ApplicationErrorCode = 0x13
	CodeKicked          quic.ApplicationErrorCode = 0x14
	CodeHostStopped     quic.ApplicationErrorCode = 0x15
	CodeProtocol        quic.ApplicationErrorCode = 0x16
	CodeApprovalTimeout quic.ApplicationErrorCode = 0x17
	CodeDuplicate       quic.ApplicationErrorCode = 0x18 // another path already won
)

// Reject reasons sent in "reject" messages; they mirror the close codes.
const (
	ReasonBadSecret       = "bad_secret"
	ReasonExpired         = "expired"
	ReasonDenied          = "denied"
	ReasonFull            = "full"
	ReasonApprovalTimeout = "approval_timeout"
	ReasonVersion         = "version"
)

// Msg is one control message. Messages are JSON objects, one per line.
//
//	guest→host: hello{v, secret, name, app}
//	host→guest: wait{} (approval pending) | admitted{motd} | reject{reason} | world{motd}
type Msg struct {
	T      string `json:"t"`
	V      int    `json:"v,omitempty"`
	Secret []byte `json:"secret,omitempty"`
	Name   string `json:"name,omitempty"`
	App    string `json:"app,omitempty"`
	MOTD   string `json:"motd,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const maxMsg = 16 << 10

// Control wraps the control stream.
type Control struct {
	s  *quic.Stream
	r  *bufio.Reader
	mu sync.Mutex
}

// NewControl wraps an already-typed control stream.
func NewControl(s *quic.Stream) *Control {
	return &Control{s: s, r: bufio.NewReaderSize(s, 4096)}
}

// Send writes one message.
func (c *Control) Send(m Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.s.Write(append(b, '\n'))
	return err
}

// Recv reads one message.
func (c *Control) Recv() (Msg, error) {
	var line []byte
	for {
		part, isPrefix, err := c.r.ReadLine()
		if err != nil {
			return Msg{}, err
		}
		line = append(line, part...)
		if len(line) > maxMsg {
			return Msg{}, errors.New("transport: control message too large")
		}
		if !isPrefix {
			break
		}
	}
	var m Msg
	if err := json.Unmarshal(line, &m); err != nil {
		return Msg{}, fmt.Errorf("transport: bad control message: %w", err)
	}
	return m, nil
}

// Stream returns the underlying stream.
func (c *Control) Stream() *quic.Stream { return c.s }

// RejectError is returned to a guest whose join the host refused.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return "host rejected join: " + e.Reason }

// GuestHello runs the guest side of the control handshake. onWait is called
// once if the host requires manual approval. It returns the control channel
// and the host's world MOTD once admitted.
func GuestHello(ctx context.Context, conn *quic.Conn, secret []byte, name, app string, onWait func()) (*Control, string, error) {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.Write([]byte{StreamControl}); err != nil {
		return nil, "", err
	}
	c := NewControl(s)
	if err := c.Send(Msg{T: "hello", V: ProtocolVersion, Secret: secret, Name: name, App: app}); err != nil {
		return nil, "", err
	}
	stop := context.AfterFunc(ctx, func() { s.CancelRead(0) })
	defer stop()
	for {
		m, err := c.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			return nil, "", closeReason(conn, err)
		}
		switch m.T {
		case "wait":
			if onWait != nil {
				onWait()
				onWait = nil
			}
		case "admitted":
			return c, m.MOTD, nil
		case "reject":
			return nil, "", &RejectError{Reason: m.Reason}
		}
	}
}

// closeReason converts a connection close into a RejectError where possible.
func closeReason(conn *quic.Conn, err error) error {
	var ae *quic.ApplicationError
	cerr := context.Cause(conn.Context())
	if cerr != nil && errors.As(cerr, &ae) || errors.As(err, &ae) {
		if r := ReasonForCode(ae.ErrorCode); r != "" {
			return &RejectError{Reason: r}
		}
	}
	return err
}

// ReasonForCode maps a close code to a reject reason ("" if none).
func ReasonForCode(c quic.ApplicationErrorCode) string {
	switch c {
	case CodeBadSecret:
		return ReasonBadSecret
	case CodeExpired:
		return ReasonExpired
	case CodeDenied:
		return ReasonDenied
	case CodeFull:
		return ReasonFull
	case CodeApprovalTimeout:
		return ReasonApprovalTimeout
	case CodeKicked:
		return "kicked"
	case CodeHostStopped:
		return "host_stopped"
	}
	return ""
}

// HostAcceptHello waits for the guest's control stream and hello message.
func HostAcceptHello(ctx context.Context, conn *quic.Conn, timeout time.Duration) (*Control, Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, Msg{}, err
	}
	stop := context.AfterFunc(ctx, func() { s.CancelRead(0) })
	defer stop()
	var t [1]byte
	if _, err := io.ReadFull(s, t[:]); err != nil {
		return nil, Msg{}, err
	}
	if t[0] != StreamControl {
		return nil, Msg{}, errors.New("transport: first stream is not a control stream")
	}
	c := NewControl(s)
	m, err := c.Recv()
	if err != nil {
		return nil, Msg{}, err
	}
	if m.T != "hello" {
		return nil, Msg{}, errors.New("transport: expected hello")
	}
	return c, m, nil
}
