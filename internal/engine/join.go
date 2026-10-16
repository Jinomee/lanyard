package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/mc/internal/brand"
	"github.com/jinomee/mc/internal/connect"
	"github.com/jinomee/mc/internal/i18n"
	"github.com/jinomee/mc/internal/joincode"
	"github.com/jinomee/mc/internal/mclan"
	"github.com/jinomee/mc/internal/proxy"
	"github.com/jinomee/mc/internal/transport"
)

// Join statuses.
const (
	JoinConnecting      = "connecting"       // trying the invite directly
	JoinNeedReply       = "need_reply"       // direct failed; reply code shown, still trying
	JoinAuthenticating  = "authenticating"   // a path is up, checking the code with the host
	JoinWaitingApproval = "waiting_approval" // host must click Allow
	JoinConnected       = "connected"
	JoinFailed          = "failed"
	JoinDisconnected    = "disconnected" // was connected, connection ended
	JoinStopped         = "stopped"
)

// ReplyLifetime is how long a guest's reply code is valid.
const ReplyLifetime = 10 * time.Minute

// HostSummary is what the invite says about the host's network.
type HostSummary struct {
	IPv6       bool   `json:"ipv6"`
	PortMapped bool   `json:"portMapped"`
	Mapping    string `json:"mapping"` // "eim", "dependent", "unknown"
	CGNAT      bool   `json:"cgnat"`
	Approval   bool   `json:"approval"`
	Dedicated  bool   `json:"dedicated"`
	Expires    string `json:"expires"`
}

// JoinState is the join session as shown to clients.
type JoinState struct {
	Status       string             `json:"status"`
	Phase        string             `json:"phase"`
	Code         string             `json:"code"`
	Host         HostSummary        `json:"host"`
	ReplyCode    string             `json:"replyCode,omitempty"`
	ReplyExpires time.Time          `json:"replyExpires,omitzero"`
	Attempts     []connect.Attempt  `json:"attempts"`
	Via          *connect.Attempt   `json:"via,omitempty"`
	LocalAddr    string             `json:"localAddr,omitempty"`
	MOTD         string             `json:"motd,omitempty"`
	Failure      *connect.Diagnosis `json:"failure,omitempty"`
	Report       *connect.Report    `json:"report,omitempty"`
	Since        time.Time          `json:"since"`
	ConnectedAt  time.Time          `json:"connectedAt,omitzero"`
	BytesUp      int64              `json:"bytesUp"`
	BytesDown    int64              `json:"bytesDown"`
}

type joinSession struct {
	e      *Engine
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	inv    *joincode.Invite
	sess   [joincode.SessionLen]byte

	mu          sync.Mutex
	status      string
	phase       string
	code        string
	replyCode   string
	replyExp    time.Time
	attempts    []connect.Attempt
	via         *connect.Attempt
	localAddr   string
	motd        string
	failure     *connect.Diagnosis
	report      *connect.Report
	since       time.Time
	connectedAt time.Time
	stats       proxy.Stats

	ep4, ep6  *transport.Endpoint
	gathered  *connect.Gathered
	listener  net.Listener
	announcer *mclan.Announcer
	conn      *quic.Conn
}

func (j *joinSession) active() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch j.status {
	case JoinFailed, JoinDisconnected, JoinStopped:
		return false
	}
	return true
}

// ParsedCode describes a pasted code for the "Join this world?" prompt.
type ParsedCode struct {
	Kind    string      `json:"kind"` // "invite" or "reply"
	Code    string      `json:"code"`
	Expires time.Time   `json:"expires"`
	Expired bool        `json:"expired"`
	Host    HostSummary `json:"host,omitzero"`
}

// ParseCode validates a code (or any text containing one).
func (e *Engine) ParseCode(text string) (*ParsedCode, error) {
	code, kind, ok := joincode.Find(text)
	if !ok {
		_, err := joincode.DecodeInvite(text)
		if err == nil {
			err = joincode.ErrPrefix
		}
		return nil, codeError(err, "err.code.invalid")
	}
	p := &ParsedCode{Kind: kind.String(), Code: code}
	if kind == joincode.KindInvite {
		inv, err := joincode.DecodeInvite(code)
		if err != nil {
			return nil, codeError(err, "err.code.invalid")
		}
		p.Expires, p.Host = inv.Expires, summarize(inv)
	} else {
		rep, err := joincode.DecodeReply(code)
		if err != nil {
			return nil, codeError(err, "err.code.invalid")
		}
		p.Expires = rep.Expires
	}
	p.Expired = joincode.Expired(p.Expires, time.Now())
	return p, nil
}

func summarize(inv *joincode.Invite) HostSummary {
	m := "unknown"
	switch {
	case inv.Flags.Has(joincode.FlagMapEIM):
		m = "eim"
	case inv.Flags.Has(joincode.FlagMapDep):
		m = "dependent"
	}
	return HostSummary{
		IPv6: inv.Flags.Has(joincode.FlagIPv6), PortMapped: inv.Flags.Has(joincode.FlagPortMapped),
		Mapping: m, CGNAT: inv.Flags.Has(joincode.FlagCGNAT), Approval: inv.Flags.Has(joincode.FlagApproval),
		Dedicated: inv.Flags.Has(joincode.FlagDedicated), Expires: inv.Expires.Format(time.RFC3339),
	}
}

// StartJoin begins joining a host with an invite code (or link). Any previous
// join session is stopped first.
func (e *Engine) StartJoin(code string) error {
	if k, err := joincode.KindOf(code); err == nil && k == joincode.KindReply {
		return userErr(http.StatusBadRequest, "err.code.is_reply")
	}
	inv, err := joincode.DecodeInvite(code)
	if err != nil {
		return codeError(err, "err.code.invalid")
	}
	if joincode.Expired(inv.Expires, time.Now()) {
		return userErr(http.StatusBadRequest, "err.code.expired")
	}
	if c, _, ok := joincode.Find(code); ok {
		code = c
	}
	e.StopJoin()
	ctx, cancel := context.WithCancel(e.ctx)
	j := &joinSession{e: e, ctx: ctx, cancel: cancel, inv: inv, status: JoinConnecting, phase: connect.PhaseDirect,
		code: code, since: time.Now(), attempts: []connect.Attempt{}}
	_, _ = rand.Read(j.sess[:])
	e.mu.Lock()
	e.join = j
	e.mu.Unlock()
	e.log.Info("joining", "candidates", inv.Candidates, "flags", inv.Flags, "expires", inv.Expires)
	j.wg.Add(1)
	go j.run()
	return nil
}

func (j *joinSession) setStatus(s string) {
	j.mu.Lock()
	if j.status != JoinStopped {
		j.status = s
	}
	j.mu.Unlock()
}

func (j *joinSession) recordAttempt(a connect.Attempt) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.attempts {
		if j.attempts[i].Strategy == a.Strategy && j.attempts[i].Addr == a.Addr {
			j.attempts[i] = a
			return
		}
	}
	j.attempts = append(j.attempts, a)
	j.e.log.Info("connect attempt", "strategy", a.Strategy, "addr", a.Addr, "phase", a.Phase,
		"outcome", a.Outcome, "tries", a.Tries, "ms", a.DurationMs, "err", a.Error)
}

func (j *joinSession) run() {
	defer j.wg.Done()
	s := j.e.settings.Get()
	ep4, err := transport.ListenUDP(4, 0)
	if err != nil {
		j.finishFailed(&connect.Diagnosis{Summary: connect.Advice{Key: "diag.fail.local_socket"}}, err)
		return
	}
	ep6, _ := transport.ListenUDP(6, 0)
	j.mu.Lock()
	j.ep4, j.ep6 = ep4, ep6
	j.mu.Unlock()

	// Gather our own candidates in parallel: they become the reply code.
	gatherDone := make(chan struct{})
	go func() {
		defer close(gatherDone)
		g := connect.Gather(j.ctx, connect.GatherOptions{
			EP4: ep4, EP6: ep6, STUNServers: s.STUNServers, PortMap: s.UPnP,
			PortMapOptions: j.e.portmapOptions(),
		})
		r := &g.Report
		j.e.log.Info("guest network", "nat", r.NATType, "mapping", r.Mapping, "public", r.PublicV4,
			"ipv6", r.IPv6, "portmap", r.PortMap, "cgnat", r.CGNAT, "candidates", g.Candidates)
		rep := &joincode.Reply{
			Expires:    time.Now().Add(ReplyLifetime).Truncate(time.Second),
			Flags:      r.Flags(),
			Session:    j.sess,
			Candidates: g.Candidates,
		}
		var code string
		if err := rep.Sign(j.inv.Secret); err == nil {
			code, _ = rep.Encode()
		}
		j.mu.Lock()
		j.gathered, j.report = g, r
		if len(g.Candidates) > 0 {
			j.replyCode, j.replyExp = code, rep.Expires
		}
		j.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(j.ctx, ReplyLifetime)
	defer cancel()
	joined, err := connect.Join(ctx, connect.JoinOptions{
		EP4: ep4, EP6: ep6, Invite: j.inv, Name: s.PlayerName, App: brand.Version, Session: j.sess,
		OnAttempt: j.recordAttempt,
		OnNeedReply: func() {
			j.mu.Lock()
			j.phase = connect.PhasePunch
			if j.status == JoinConnecting {
				j.status = JoinNeedReply
			}
			j.mu.Unlock()
			j.e.log.Info("direct connection not possible yet; reply code needed")
		},
		OnConnected: func(a connect.Attempt) {
			j.e.log.Info("path established", "strategy", a.Strategy, "addr", a.Addr)
			j.setStatus(JoinAuthenticating)
		},
		OnWaitApproval: func() { j.setStatus(JoinWaitingApproval) },
	})
	<-gatherDone
	if err != nil {
		var re *transport.RejectError
		var d connect.Diagnosis
		switch {
		case errors.As(err, &re):
			d = connect.DiagnoseRejection(re.Reason)
		case j.ctx.Err() != nil:
			j.release() // stopped by the user; frees a late port mapping too
			return
		default:
			j.mu.Lock()
			d = connect.DiagnoseJoin(j.report, j.inv, j.attempts, j.phase == connect.PhasePunch && j.replyCode != "")
			j.mu.Unlock()
		}
		j.finishFailed(&d, err)
		return
	}
	j.connected(joined)
}

func (j *joinSession) finishFailed(d *connect.Diagnosis, err error) {
	j.mu.Lock()
	if j.status != JoinStopped {
		j.status = JoinFailed
		j.failure = d
	}
	j.mu.Unlock()
	j.e.log.Warn("join failed", "summary", d.Summary.Key, "advice", d.Advice, "err", err)
	j.release()
}

func (j *joinSession) connected(jn *connect.Joined) {
	s := j.e.settings.Get()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(s.GuestPort)))
	if err != nil && s.GuestPort != 0 {
		j.e.log.Warn("guest port busy; using a random one", "port", s.GuestPort, "err", err)
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		_ = jn.Conn.CloseWithError(transport.CodeNormal, "")
		j.finishFailed(&connect.Diagnosis{Summary: connect.Advice{Key: "diag.fail.local_socket"}}, err)
		return
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // TCP port
	motd := i18n.T(j.e.lang(), "lan.via", "motd", mclan.SanitizeMOTD(jn.MOTD))
	ann, err := mclan.StartAnnouncer(port, motd)
	if err != nil {
		j.e.log.Warn("LAN announcement unavailable", "err", err)
	}
	j.e.mu.Lock()
	if j.e.host != nil {
		if d := j.e.host.detectorRef(); d != nil {
			d.Ignore(port, true)
		}
	}
	j.e.mu.Unlock()
	via := jn.Via
	j.mu.Lock()
	if j.status == JoinStopped {
		j.mu.Unlock()
		_ = ln.Close()
		if ann != nil {
			_ = ann.Close()
		}
		_ = jn.Conn.CloseWithError(transport.CodeNormal, "")
		return
	}
	j.listener, j.announcer, j.conn = ln, ann, jn.Conn
	j.localAddr, j.motd, j.via = ln.Addr().String(), jn.MOTD, &via
	j.status, j.connectedAt = JoinConnected, time.Now()
	j.mu.Unlock()
	j.e.log.Info("joined", "via", via.Strategy, "addr", via.Addr, "phase", via.Phase, "local", ln.Addr().String(), "motd", jn.MOTD)

	j.wg.Add(1)
	go func() { // Minecraft → host
		defer j.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.OpenGuest(j.ctx, jn.Conn, c, &j.stats)
		}
	}()
	// Control messages until the connection ends.
	reason := "lost"
	for {
		m, err := jn.Ctl.Recv()
		if err != nil {
			// The stream error and the connection's close cause race; wait
			// briefly for the connection to report why it ended.
			select {
			case <-jn.Conn.Context().Done():
			case <-time.After(time.Second):
			}
			var ae *quic.ApplicationError
			if errors.As(err, &ae) || errors.As(context.Cause(jn.Conn.Context()), &ae) {
				if r := transport.ReasonForCode(ae.ErrorCode); ae.Remote && r != "" {
					reason = r
				}
			}
			break
		}
		if m.T == "world" && m.MOTD != "" {
			j.mu.Lock()
			j.motd = m.MOTD
			j.mu.Unlock()
			if ann != nil {
				ann.SetMOTD(i18n.T(j.e.lang(), "lan.via", "motd", mclan.SanitizeMOTD(m.MOTD)))
			}
		}
	}
	j.mu.Lock()
	if j.status != JoinStopped {
		j.status = JoinDisconnected
		j.failure = &connect.Diagnosis{Summary: connect.Advice{Key: "diag.disconnected." + reason}}
	}
	j.mu.Unlock()
	j.e.log.Info("disconnected from host", "reason", reason)
	j.release()
}

// release frees sockets, the listener and the announcer.
func (j *joinSession) release() {
	j.mu.Lock()
	ln, ann, conn, ep4, ep6, g := j.listener, j.announcer, j.conn, j.ep4, j.ep6, j.gathered
	j.listener, j.announcer, j.conn, j.ep4, j.ep6 = nil, nil, nil, nil, nil
	if g != nil {
		j.gathered = &connect.Gathered{Report: g.Report, Candidates: g.Candidates} // mapping released below
	}
	j.mu.Unlock()
	if ln != nil {
		port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // TCP port
		_ = ln.Close()
		j.e.mu.Lock()
		if j.e.host != nil {
			if d := j.e.host.detectorRef(); d != nil {
				d.Ignore(port, false)
			}
		}
		j.e.mu.Unlock()
	}
	if ann != nil {
		_ = ann.Close()
	}
	if conn != nil {
		_ = conn.CloseWithError(transport.CodeNormal, "")
	}
	if g != nil && g.Mapping != nil {
		_ = g.Mapping.Close()
	}
	if ep4 != nil {
		_ = ep4.Close()
	}
	if ep6 != nil {
		_ = ep6.Close()
	}
}

// StopJoin leaves the host (or cancels connecting).
func (e *Engine) StopJoin() {
	e.mu.Lock()
	j := e.join
	e.mu.Unlock()
	if j == nil {
		return
	}
	j.mu.Lock()
	was := j.status
	j.status = JoinStopped
	j.mu.Unlock()
	j.cancel()
	j.release()
	j.wg.Wait()
	if was != JoinStopped {
		e.log.Info("join stopped")
	}
}

func (j *joinSession) state() JoinState {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := JoinState{
		Status: j.status, Phase: j.phase, Code: j.code, Host: summarize(j.inv),
		Attempts: append([]connect.Attempt(nil), j.attempts...), Via: j.via, LocalAddr: j.localAddr,
		MOTD: j.motd, Failure: j.failure, Report: j.report, Since: j.since, ConnectedAt: j.connectedAt,
		BytesUp: j.stats.Up.Load(), BytesDown: j.stats.Down.Load(),
	}
	if j.phase == connect.PhasePunch && (j.status == JoinNeedReply || j.status == JoinFailed) {
		s.ReplyCode, s.ReplyExpires = j.replyCode, j.replyExp
	}
	return s
}

func (h *hostSession) detectorRef() *mclan.Detector {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.detector
}

// ignoreJoinPorts excludes an active guest listener from a new detector.
func (e *Engine) ignoreJoinPorts(d *mclan.Detector) {
	e.mu.Lock()
	j := e.join
	e.mu.Unlock()
	if j == nil {
		return
	}
	j.mu.Lock()
	ln := j.listener
	j.mu.Unlock()
	if ln != nil {
		d.Ignore(uint16(ln.Addr().(*net.TCPAddr).Port), true) //nolint:gosec // TCP port
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
