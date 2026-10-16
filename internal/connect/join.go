package connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/mc/internal/joincode"
	"github.com/jinomee/mc/internal/transport"
)

// Strategy names, in happy-eyeballs preference order.
const (
	StratIPv6     = "ipv6"
	StratMapped   = "mapped"
	StratReflex   = "reflexive"
	StratLAN      = "lan"
	StratPeerRefl = "peer-reflexive"
	StratRelay    = "relay" // v1.1
)

// Phases of a join.
const (
	PhaseDirect = "direct" // one-way invite only
	PhasePunch  = "punch"  // reply code issued, both sides punching
)

// Attempt outcomes.
const (
	OutPending      = "pending"
	OutOK           = "ok"
	OutTimeout      = "timeout"
	OutRefused      = "refused"
	OutUnreachable  = "unreachable"
	OutCertMismatch = "cert_mismatch"
	OutNoIPv6       = "no_ipv6"
	OutCancelled    = "cancelled"
	OutError        = "error"
)

// Attempt records the history of dialing one candidate path.
type Attempt struct {
	Strategy   string    `json:"strategy"`
	Addr       string    `json:"addr"`
	Phase      string    `json:"phase"`
	Started    time.Time `json:"started"`
	DurationMs int64     `json:"durationMs"` // of the latest try
	Tries      int       `json:"tries"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
}

func strategyFor(k joincode.CandidateKind) string {
	switch k {
	case joincode.CandIPv6:
		return StratIPv6
	case joincode.CandMapped:
		return StratMapped
	case joincode.CandReflexive:
		return StratReflex
	case joincode.CandLAN:
		return StratLAN
	}
	return "unknown"
}

// stagger is the happy-eyeballs start delay per strategy.
func stagger(s string) time.Duration {
	switch s {
	case StratIPv6:
		return 0
	case StratMapped:
		return 50 * time.Millisecond
	case StratReflex:
		return 100 * time.Millisecond
	case StratLAN:
		return 150 * time.Millisecond
	}
	return 0
}

// JoinOptions configures Join.
type JoinOptions struct {
	EP4, EP6 *transport.Endpoint // EP6 may be nil
	Invite   *joincode.Invite
	Name     string
	App      string
	// Session identifies this guest's reply code; host punches carry it.
	Session [joincode.SessionLen]byte
	// DirectTimeout is how long the one-way invite gets before OnNeedReply.
	DirectTimeout time.Duration
	// HandshakeTimeout bounds each QUIC dial try.
	HandshakeTimeout time.Duration
	// OnAttempt receives every attempt update (copy).
	OnAttempt func(Attempt)
	// OnNeedReply is called once when the direct phase timed out.
	OnNeedReply func()
	// OnWaitApproval is called if the host must approve the join.
	OnWaitApproval func()
	// OnConnected is called when a QUIC path is up, before authentication.
	OnConnected func(Attempt)
	// OnPunch is called for every valid punch packet from the host.
	OnPunch func(from netip.AddrPort)
}

// Joined is a successful, authenticated connection to a host.
type Joined struct {
	Conn *quic.Conn
	Ctl  *transport.Control
	MOTD string
	Via  Attempt
}

type path struct {
	strategy string
	addr     netip.AddrPort
}

type joiner struct {
	opt      JoinOptions
	ctx      context.Context
	mu       sync.Mutex
	attempts map[netip.AddrPort]*Attempt // one path per address
	pokes    map[netip.AddrPort]chan struct{}
	phase    string
	winner   chan won
	wg       sync.WaitGroup
}

type won struct {
	conn *quic.Conn
	att  Attempt
}

// Join dials every candidate of the invite in parallel and returns the first
// authenticated connection. It keeps retrying (and accepting peer-reflexive
// candidates learned from host punches) until ctx ends.
func Join(ctx context.Context, opt JoinOptions) (*Joined, error) {
	if opt.DirectTimeout == 0 {
		opt.DirectTimeout = 6 * time.Second
	}
	if opt.HandshakeTimeout == 0 {
		opt.HandshakeTimeout = 4 * time.Second
	}
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	j := &joiner{opt: opt, ctx: actx, attempts: map[netip.AddrPort]*Attempt{}, pokes: map[netip.AddrPort]chan struct{}{},
		phase: PhaseDirect, winner: make(chan won, 1)}

	// Peer-reflexive learning: a valid host punch reveals the address the
	// host's NAT actually uses toward us.
	learn := func(p transport.Packet) {
		role, sess, ok := transport.ParsePunch(opt.Invite.Secret, p.Data)
		if !ok || role != transport.RoleHost || sess != opt.Session {
			return
		}
		if opt.OnPunch != nil {
			opt.OnPunch(p.From)
		}
		j.startPath(path{StratPeerRefl, p.From}, 0)
	}
	opt.EP4.OnPunch(learn)
	defer opt.EP4.OnPunch(nil)
	if opt.EP6 != nil {
		opt.EP6.OnPunch(learn)
		defer opt.EP6.OnPunch(nil)
	}

	for _, c := range opt.Invite.Candidates {
		s := strategyFor(c.Kind)
		j.startPath(path{s, c.Addr}, stagger(s))
	}
	// Guest punches keep our own NAT open toward every host candidate.
	j.wg.Add(1)
	go j.punchLoop()

	directTimer := time.NewTimer(opt.DirectTimeout)
	defer directTimer.Stop()
	var w won
wait:
	for {
		select {
		case w = <-j.winner:
			break wait
		case <-directTimer.C:
			j.mu.Lock()
			j.phase = PhasePunch
			j.mu.Unlock()
			if opt.OnNeedReply != nil {
				opt.OnNeedReply()
			}
		case <-ctx.Done():
			cancel()
			j.wg.Wait()
			select {
			case w := <-j.winner:
				_ = w.conn.CloseWithError(transport.CodeNormal, "")
			default:
			}
			return nil, ctx.Err()
		}
	}
	cancel() // stop the other paths
	j.wg.Wait()
	if opt.OnConnected != nil {
		opt.OnConnected(w.att)
	}
	ctl, motd, err := transport.GuestHello(ctx, w.conn, opt.Invite.Secret[:], opt.Name, opt.App, opt.OnWaitApproval)
	if err != nil {
		_ = w.conn.CloseWithError(transport.CodeNormal, "")
		return nil, err
	}
	return &Joined{Conn: w.conn, Ctl: ctl, MOTD: motd, Via: w.att}, nil
}

func (j *joiner) snapshot(a *Attempt) Attempt {
	j.mu.Lock()
	defer j.mu.Unlock()
	return *a
}

// startPath dials a new address. If the address is already being tried (a
// host punch from an address we know), that path retries right away instead:
// the punch means the host's NAT has just opened.
func (j *joiner) startPath(p path, delay time.Duration) {
	j.mu.Lock()
	if j.ctx.Err() != nil {
		j.mu.Unlock()
		return
	}
	if _, dup := j.attempts[p.addr]; dup {
		poke := j.pokes[p.addr]
		j.mu.Unlock()
		select {
		case poke <- struct{}{}:
		default:
		}
		return
	}
	a := &Attempt{Strategy: p.strategy, Addr: p.addr.String(), Phase: j.phase, Outcome: OutPending, Started: time.Now()}
	poke := make(chan struct{}, 1)
	j.attempts[p.addr], j.pokes[p.addr] = a, poke
	j.wg.Add(1)
	j.mu.Unlock()
	go j.run(p, a, delay, poke)
}

func (j *joiner) report(a *Attempt) {
	if j.opt.OnAttempt != nil {
		j.opt.OnAttempt(j.snapshot(a))
	}
}

func (j *joiner) endpointFor(ap netip.AddrPort) *transport.Endpoint {
	if ap.Addr().Is4() {
		return j.opt.EP4
	}
	return j.opt.EP6
}

func (j *joiner) run(p path, a *Attempt, delay time.Duration, poke <-chan struct{}) {
	defer j.wg.Done()
	ep := j.endpointFor(p.addr)
	if ep == nil {
		j.mu.Lock()
		a.Outcome, a.Error = OutNoIPv6, "this computer has no IPv6 connectivity"
		j.mu.Unlock()
		j.report(a)
		return
	}
	select {
	case <-time.After(delay):
	case <-j.ctx.Done():
		return
	}
	backoff := time.Second
	for {
		j.mu.Lock()
		a.Tries++
		a.Phase = j.phase
		j.mu.Unlock()
		t0 := time.Now()
		dctx, dcancel := context.WithTimeout(j.ctx, j.opt.HandshakeTimeout)
		conn, err := ep.Transport().Dial(dctx, net.UDPAddrFromAddrPort(p.addr), transport.ClientTLS(j.opt.Invite.Fingerprint), transport.QUICConfig())
		dcancel()
		j.mu.Lock()
		a.DurationMs = time.Since(t0).Milliseconds()
		a.Phase = j.phase // the phase in which this try ended
		if err == nil {
			a.Outcome, a.Error = OutOK, ""
		} else if j.ctx.Err() != nil {
			if a.Outcome == OutPending {
				a.Outcome = OutCancelled
			}
		} else {
			a.Outcome, a.Error = classify(err), shortError(err)
		}
		out := a.Outcome
		snap := *a
		j.mu.Unlock()
		j.report(a)
		if err == nil {
			select {
			case j.winner <- won{conn, snap}:
			default:
				_ = conn.CloseWithError(transport.CodeDuplicate, "another path won")
			}
			return
		}
		if j.ctx.Err() != nil || out == OutCertMismatch {
			return
		}
		select {
		case <-time.After(backoff):
		case <-poke:
		case <-j.ctx.Done():
			return
		}
		if time.Since(a.Started) > time.Minute {
			backoff = 3 * time.Second
		}
	}
}

func (j *joiner) punchLoop() {
	defer j.wg.Done()
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-j.ctx.Done():
			return
		case <-t.C:
		}
		pkt := transport.MakePunch(j.opt.Invite.Secret, transport.RoleGuest, j.opt.Session)
		for _, c := range j.opt.Invite.Candidates {
			if ep := j.endpointFor(c.Addr); ep != nil {
				_ = ep.WriteTo(pkt, c.Addr)
			}
		}
	}
}

func classify(err error) string {
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	switch {
	case errors.As(err, &idle), errors.As(err, &hs), errors.Is(err, context.DeadlineExceeded):
		return OutTimeout
	case strings.Contains(err.Error(), transport.ErrFingerprint.Error()):
		return OutCertMismatch
	case errors.Is(err, syscall.ECONNREFUSED):
		return OutRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return OutUnreachable
	}
	return OutError
}

func shortError(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
