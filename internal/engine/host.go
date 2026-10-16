package engine

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jinomee/lanyard/internal/connect"
	"github.com/jinomee/lanyard/internal/i18n"
	"github.com/jinomee/lanyard/internal/joincode"
	"github.com/jinomee/lanyard/internal/mclan"
	"github.com/jinomee/lanyard/internal/proxy"
	"github.com/jinomee/lanyard/internal/transport"
)

// MaxGuests is the number of friends one host admits (8 players in total).
const MaxGuests = 7

// Host modes.
const (
	ModeAuto   = "auto"   // follow the "Open to LAN" world
	ModeManual = "manual" // fixed port (dedicated server)
)

// Host statuses.
const (
	HostStarting   = "starting"
	HostReady      = "ready"
	HostRefreshing = "refreshing"
	HostError      = "error"
	HostStopped    = "stopped"
)

// HostState is the host session as shown to clients.
type HostState struct {
	Status       string             `json:"status"`
	Error        *UserError         `json:"error,omitempty"`
	Mode         string             `json:"mode"`
	ManualPort   int                `json:"manualPort"`
	Worlds       []mclan.World      `json:"worlds"`
	LANDetection bool               `json:"lanDetection"`
	Target       string             `json:"target,omitempty"`
	TargetMOTD   string             `json:"targetMotd,omitempty"`
	TargetOK     bool               `json:"targetOk"`
	Code         string             `json:"code,omitempty"`
	Link         string             `json:"link,omitempty"`
	Expires      time.Time          `json:"expires,omitzero"`
	Approval     bool               `json:"approval"`
	Guests       []GuestInfo        `json:"guests"`
	Pending      []GuestInfo        `json:"pending"`
	Punches      []PunchInfo        `json:"punches"`
	Report       *connect.Report    `json:"report,omitempty"`
	Outlook      *connect.Diagnosis `json:"outlook,omitempty"`
	UDPPort      int                `json:"udpPort"`
	BytesUp      int64              `json:"bytesUp"`
	BytesDown    int64              `json:"bytesDown"`
	Since        time.Time          `json:"since"`
}

// GuestInfo describes a connected or waiting guest.
type GuestInfo struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Addr  string    `json:"addr"`
	Since time.Time `json:"since"`
}

// PunchInfo describes a reply code the host is punching toward.
type PunchInfo struct {
	ID      string    `json:"id"`
	Started time.Time `json:"started"`
	Targets []string  `json:"targets"`
	Active  bool      `json:"active"`
}

type guestConn struct {
	info GuestInfo
	conn *quic.Conn
	ctl  *transport.Control
}

type pendingJoin struct {
	info   GuestInfo
	decide chan bool
}

type hostSession struct {
	e      *Engine
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	status     string
	err        *UserError
	mode       string
	manualPort int
	ep4, ep6   *transport.Endpoint
	gathered   *connect.Gathered
	detector   *mclan.Detector
	invite     *joincode.Invite
	code       string
	guests     map[string]*guestConn
	pending    map[string]*pendingJoin
	punches    []*PunchInfo
	stats      proxy.Stats
	lastTarget netip.AddrPort
	lastMOTD   string
	targetOK   bool
	since      time.Time
}

func (h *hostSession) active() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status != HostStopped && h.status != HostError
}

// StartHost starts hosting. mode is ModeAuto or ModeManual; manualPort is
// used in manual mode (0 = the setting).
func (e *Engine) StartHost(mode string, manualPort int) error {
	if mode == "" {
		mode = ModeAuto
	}
	if mode != ModeAuto && mode != ModeManual {
		return userErr(http.StatusBadRequest, "err.host.mode")
	}
	s := e.settings.Get()
	if manualPort == 0 {
		manualPort = s.ManualPort
	}
	if manualPort < 1 || manualPort > 65535 {
		return userErr(http.StatusBadRequest, "settings.err.manualPort")
	}
	e.mu.Lock()
	if e.host != nil && e.host.active() {
		e.mu.Unlock()
		return userErr(http.StatusConflict, "err.host.already")
	}
	ctx, cancel := context.WithCancel(e.ctx)
	h := &hostSession{e: e, ctx: ctx, cancel: cancel, status: HostStarting, mode: mode, manualPort: manualPort,
		guests: map[string]*guestConn{}, pending: map[string]*pendingJoin{}, since: time.Now()}
	e.host = h
	e.mu.Unlock()
	e.log.Info("hosting started", "mode", mode, "manualPort", manualPort)
	go h.run()
	return nil
}

// SetHostTarget changes the mode/port of the running host.
func (e *Engine) SetHostTarget(mode string, manualPort int) error {
	h := e.currentHost()
	if h == nil {
		return userErr(http.StatusConflict, "err.host.not_running")
	}
	if mode != ModeAuto && mode != ModeManual {
		return userErr(http.StatusBadRequest, "err.host.mode")
	}
	if mode == ModeManual && (manualPort < 1 || manualPort > 65535) {
		return userErr(http.StatusBadRequest, "settings.err.manualPort")
	}
	h.mu.Lock()
	h.mode = mode
	if manualPort > 0 {
		h.manualPort = manualPort
	}
	h.mu.Unlock()
	e.log.Info("host target changed", "mode", mode, "manualPort", manualPort)
	return nil
}

func (e *Engine) currentHost() *hostSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.host == nil || !e.host.active() {
		return nil
	}
	return e.host
}

func (h *hostSession) fail(key string, err error) {
	h.mu.Lock()
	h.status = HostError
	h.err = &UserError{Key: key}
	if err != nil {
		h.err.Detail = err.Error()
	}
	h.mu.Unlock()
	h.e.log.Error("hosting failed", "key", key, "err", err)
	h.cancel()
	h.cleanup()
}

func (h *hostSession) run() {
	s := h.e.settings.Get()
	ep4, err := transport.ListenUDP(4, s.UDPPort)
	if err != nil {
		h.fail("err.host.udp_port", err)
		return
	}
	ep6, err := transport.ListenUDP(6, int(ep4.Port()))
	if err != nil {
		ep6, _ = transport.ListenUDP(6, 0)
	}
	h.mu.Lock()
	h.ep4, h.ep6 = ep4, ep6
	h.mu.Unlock()

	h.e.mu.Lock()
	id := h.e.id
	h.e.mu.Unlock()
	for _, ep := range []*transport.Endpoint{ep4, ep6} {
		if ep == nil {
			continue
		}
		ln, err := ep.Transport().Listen(transport.ServerTLS(id), transport.QUICConfig())
		if err != nil {
			h.fail("err.host.listen", err)
			return
		}
		h.wg.Add(1)
		go h.acceptLoop(ln)
	}

	if d, err := mclan.ListenDetector(); err != nil {
		h.e.log.Warn("LAN world detection unavailable", "err", err)
	} else {
		h.mu.Lock()
		h.detector = d
		h.mu.Unlock()
		h.e.ignoreJoinPorts(d)
	}

	if err := h.regather(); err != nil {
		h.fail("err.host.no_network", err)
		return
	}
	h.wg.Add(2)
	go h.watchTarget()
	go h.expireLoop()
}

// regather discovers candidates and issues a fresh invite (revoking the old one).
func (h *hostSession) regather() error {
	s := h.e.settings.Get()
	h.mu.Lock()
	old := h.gathered
	ep4, ep6 := h.ep4, h.ep6
	h.mu.Unlock()
	if old != nil && old.Mapping != nil {
		_ = old.Mapping.Close()
	}
	g := connect.Gather(h.ctx, connect.GatherOptions{
		EP4: ep4, EP6: ep6, STUNServers: s.STUNServers, PortMap: s.UPnP,
		PortMapOptions: h.e.portmapOptions(), ProbeFiltering: true,
	})
	r := &g.Report
	h.e.log.Info("host network", "nat", r.NATType, "mapping", r.Mapping, "filtering", r.Filtering,
		"public", r.PublicV4, "ipv6", r.IPv6, "portmap", r.PortMap, "cgnat", r.CGNAT, "reason", r.CGNATReason,
		"udpBlocked", r.UDPBlocked, "candidates", g.Candidates, "ms", r.ElapsedMs)
	for _, x := range append(r.STUN4, r.STUN6...) {
		h.e.log.Debug("stun", "server", x.Server, "resolved", x.Resolved, "mapped", x.Mapped, "rttMs", x.RTTms, "err", x.Error)
	}
	if h.ctx.Err() != nil {
		if g.Mapping != nil {
			_ = g.Mapping.Close()
		}
		return h.ctx.Err()
	}
	if len(g.Candidates) == 0 {
		if g.Mapping != nil {
			_ = g.Mapping.Close()
		}
		return errors.New("no usable address")
	}
	inv := &joincode.Invite{
		Expires:     time.Now().Add(time.Duration(s.InviteHours) * time.Hour).Truncate(time.Second),
		Flags:       r.Flags(),
		Fingerprint: h.e.id.Fingerprint(),
		Candidates:  g.Candidates,
	}
	if s.RequireApproval {
		inv.Flags |= joincode.FlagApproval
	}
	h.mu.Lock()
	if h.mode == ModeManual {
		inv.Flags |= joincode.FlagDedicated
	}
	h.mu.Unlock()
	if _, err := rand.Read(inv.Secret[:]); err != nil {
		return err
	}
	code, err := inv.Encode()
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.gathered, h.invite, h.code = g, inv, code
	h.status = HostReady
	h.mu.Unlock()
	h.e.log.Info("invite issued", "expires", inv.Expires, "candidates", len(inv.Candidates), "flags", inv.Flags)
	return nil
}

// NewCode revokes the current code and issues a new one (re-checking the network).
func (e *Engine) NewCode() error {
	h := e.currentHost()
	if h == nil {
		return userErr(http.StatusConflict, "err.host.not_running")
	}
	h.mu.Lock()
	if h.status != HostReady {
		h.mu.Unlock()
		return userErr(http.StatusConflict, "err.host.busy")
	}
	h.status = HostRefreshing
	h.mu.Unlock()
	e.log.Info("code revoked; issuing a new one")
	go func() {
		if err := h.regather(); err != nil && h.ctx.Err() == nil {
			h.fail("err.host.no_network", err)
		}
	}()
	return nil
}

func (h *hostSession) acceptLoop(ln *quic.Listener) {
	defer h.wg.Done()
	defer func() { _ = ln.Close() }()
	for {
		conn, err := ln.Accept(h.ctx)
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handle(conn)
		}()
	}
}

func reject(conn *quic.Conn, ctl *transport.Control, reason string, code quic.ApplicationErrorCode) {
	_ = ctl.Send(transport.Msg{T: "reject", Reason: reason})
	time.Sleep(100 * time.Millisecond) // let the message go out before CONNECTION_CLOSE
	_ = conn.CloseWithError(code, reason)
}

func (h *hostSession) handle(conn *quic.Conn) {
	remote := conn.RemoteAddr().String()
	ctl, hello, err := transport.HostAcceptHello(h.ctx, conn, 10*time.Second)
	if err != nil {
		h.e.log.Debug("connection without valid hello", "remote", remote, "err", err)
		_ = conn.CloseWithError(transport.CodeProtocol, "")
		return
	}
	name := mclan.SanitizeMOTD(hello.Name)
	if len([]rune(name)) > 32 {
		name = string([]rune(name)[:32])
	}
	log := h.e.log.With("guest", name, "remote", remote, "app", hello.App)
	h.mu.Lock()
	inv := h.invite
	nGuests := len(h.guests) + len(h.pending)
	h.mu.Unlock()
	switch {
	case hello.V != transport.ProtocolVersion:
		log.Info("join rejected: protocol version", "v", hello.V)
		reject(conn, ctl, transport.ReasonVersion, transport.CodeProtocol)
		return
	case inv == nil || subtle.ConstantTimeCompare(hello.Secret, inv.Secret[:]) != 1:
		log.Info("join rejected: wrong or revoked code")
		reject(conn, ctl, transport.ReasonBadSecret, transport.CodeBadSecret)
		return
	case joincode.Expired(inv.Expires, time.Now()):
		log.Info("join rejected: code expired")
		reject(conn, ctl, transport.ReasonExpired, transport.CodeExpired)
		return
	case nGuests >= MaxGuests:
		log.Info("join rejected: full")
		reject(conn, ctl, transport.ReasonFull, transport.CodeFull)
		return
	}
	info := GuestInfo{ID: randomID(), Name: name, Addr: remote, Since: time.Now()}
	if h.e.settings.Get().RequireApproval {
		p := &pendingJoin{info: info, decide: make(chan bool, 1)}
		h.mu.Lock()
		h.pending[info.ID] = p
		h.mu.Unlock()
		_ = ctl.Send(transport.Msg{T: "wait"})
		log.Info("join waiting for approval")
		var allow, decided bool
		select {
		case allow = <-p.decide:
			decided = true
		case <-time.After(2 * time.Minute):
		case <-conn.Context().Done():
		case <-h.ctx.Done():
		}
		h.mu.Lock()
		delete(h.pending, info.ID)
		h.mu.Unlock()
		if !allow {
			if decided {
				log.Info("join denied by host")
				reject(conn, ctl, transport.ReasonDenied, transport.CodeDenied)
			} else {
				log.Info("join approval timed out")
				reject(conn, ctl, transport.ReasonApprovalTimeout, transport.CodeApprovalTimeout)
			}
			return
		}
		info.Since = time.Now()
	}
	g := &guestConn{info: info, conn: conn, ctl: ctl}
	h.mu.Lock()
	if h.ctx.Err() != nil {
		h.mu.Unlock()
		_ = conn.CloseWithError(transport.CodeHostStopped, "")
		return
	}
	h.guests[info.ID] = g
	motd := h.motdLocked()
	h.mu.Unlock()
	if err := ctl.Send(transport.Msg{T: "admitted", MOTD: motd}); err != nil {
		h.removeGuest(info.ID)
		return
	}
	log.Info("guest joined")
	go func() { // drain the control stream; ends when the guest leaves
		for {
			if _, err := ctl.Recv(); err != nil {
				return
			}
		}
	}()
	err = proxy.ServeHost(h.ctx, conn, h.dial, &h.stats)
	h.removeGuest(info.ID)
	log.Info("guest left", "reason", errString(err))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (h *hostSession) removeGuest(id string) {
	h.mu.Lock()
	delete(h.guests, id)
	h.mu.Unlock()
}

// dial connects to the current Minecraft target.
func (h *hostSession) dial(ctx context.Context) (net.Conn, error) {
	t := h.target()
	if !t.IsValid() {
		return nil, errors.New("no Minecraft world open to LAN")
	}
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return d.DialContext(ctx, "tcp", t.String())
}

// target returns where guests' connections go right now.
func (h *hostSession) target() netip.AddrPort {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, _ := h.targetLocked()
	return t
}

func (h *hostSession) targetLocked() (netip.AddrPort, string) {
	if h.mode == ModeManual {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.manualPort)), "" //nolint:gosec // validated 1..65535
	}
	if h.detector != nil {
		if w, ok := pickWorld(h.detector.Worlds(), h.lastTarget); ok {
			h.lastTarget, h.lastMOTD = w.Target(), w.MOTD
			return h.lastTarget, h.lastMOTD
		}
	}
	return netip.AddrPort{}, ""
}

// pickWorld chooses the world to share from the detected ones (local first,
// newest first). Only worlds opened on this computer are ever shared: a world
// a roommate opened on the same Wi-Fi must never be put on the internet.
func pickWorld(ws []mclan.World, last netip.AddrPort) (mclan.World, bool) {
	var first *mclan.World
	for i := range ws {
		w := &ws[i]
		if !w.Local {
			continue
		}
		// Stick with the world friends are already playing in while it is
		// still open; another world opening later must not hijack them.
		if w.Target() == last {
			return *w, true
		}
		if first == nil {
			first = w
		}
	}
	// Otherwise (first world, or the world was reopened on a new port)
	// follow the most recently opened local world.
	if first != nil {
		return *first, true
	}
	return mclan.World{}, false
}

func (h *hostSession) motdLocked() string {
	if h.mode == ModeManual {
		return i18n.T(h.e.lang(), "lan.manual_motd", "name", h.e.settings.Get().PlayerName)
	}
	_, m := h.targetLocked()
	if m == "" {
		m = h.lastMOTD
	}
	return m
}

// watchTarget tells guests when the world's MOTD changes and, in manual mode,
// checks that something is listening on the port.
func (h *hostSession) watchTarget() {
	defer h.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	sent := ""
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		mode, motd := h.mode, h.motdLocked()
		target, _ := h.targetLocked()
		var ctls []*transport.Control
		if motd != sent && motd != "" {
			for _, g := range h.guests {
				ctls = append(ctls, g.ctl)
			}
			sent = motd
		}
		h.mu.Unlock()
		for _, c := range ctls {
			_ = c.Send(transport.Msg{T: "world", MOTD: motd})
		}
		ok := target.IsValid()
		if mode == ModeManual && ok {
			c, err := net.DialTimeout("tcp", target.String(), time.Second)
			ok = err == nil
			if c != nil {
				_ = c.Close()
			}
		}
		h.mu.Lock()
		h.targetOK = ok
		h.mu.Unlock()
	}
}

// expireLoop re-issues the code when it expires so hosting can run for days.
func (h *hostSession) expireLoop() {
	defer h.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		expired := h.invite != nil && h.status == HostReady && joincode.Expired(h.invite.Expires, time.Now())
		h.mu.Unlock()
		if expired {
			h.e.log.Info("invite expired; issuing a new one")
			_ = h.e.NewCode()
		}
	}
}

// SubmitReply starts hole punching toward a guest's reply code.
func (e *Engine) SubmitReply(code string) error {
	h := e.currentHost()
	if h == nil {
		return userErr(http.StatusConflict, "err.host.not_running")
	}
	if k, err := joincode.KindOf(code); err == nil && k == joincode.KindInvite {
		return userErr(http.StatusBadRequest, "err.reply.is_invite")
	}
	rep, err := joincode.DecodeReply(code)
	if err != nil {
		return codeError(err, "err.reply.invalid")
	}
	h.mu.Lock()
	inv := h.invite
	ep4, ep6 := h.ep4, h.ep6
	h.mu.Unlock()
	if inv == nil {
		return userErr(http.StatusConflict, "err.host.busy")
	}
	if !rep.Verify(inv.Secret) {
		return userErr(http.StatusBadRequest, "err.reply.wrong_code")
	}
	if joincode.Expired(rep.Expires, time.Now()) {
		return userErr(http.StatusBadRequest, "err.reply.expired")
	}
	p := &PunchInfo{ID: randomID(), Started: time.Now(), Active: true}
	for _, c := range rep.Candidates {
		p.Targets = append(p.Targets, c.String())
	}
	h.mu.Lock()
	h.punches = append(h.punches, p)
	if len(h.punches) > 10 {
		h.punches = h.punches[len(h.punches)-10:]
	}
	h.mu.Unlock()
	e.log.Info("reply code accepted; punching", "targets", p.Targets, "guestFlags", rep.Flags)
	go func() {
		connect.HostPunch(h.ctx, connect.PunchOptions{EP4: ep4, EP6: ep6, Secret: inv.Secret, Reply: rep})
		h.mu.Lock()
		p.Active = false
		h.mu.Unlock()
	}()
	return nil
}

// Approve answers a pending join.
func (e *Engine) Approve(id string, allow bool) error {
	h := e.currentHost()
	if h == nil {
		return userErr(http.StatusConflict, "err.host.not_running")
	}
	h.mu.Lock()
	p := h.pending[id]
	h.mu.Unlock()
	if p == nil {
		return userErr(http.StatusNotFound, "err.host.no_such_guest")
	}
	select {
	case p.decide <- allow:
	default:
	}
	return nil
}

// Kick disconnects a guest.
func (e *Engine) Kick(id string) error {
	h := e.currentHost()
	if h == nil {
		return userErr(http.StatusConflict, "err.host.not_running")
	}
	h.mu.Lock()
	g := h.guests[id]
	h.mu.Unlock()
	if g == nil {
		return userErr(http.StatusNotFound, "err.host.no_such_guest")
	}
	e.log.Info("guest kicked", "guest", g.info.Name)
	return g.conn.CloseWithError(transport.CodeKicked, "kicked")
}

// StopHost stops hosting and disconnects everyone.
func (e *Engine) StopHost() {
	e.mu.Lock()
	h := e.host
	e.mu.Unlock()
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.status == HostStopped {
		h.mu.Unlock()
		return
	}
	h.status = HostStopped
	h.mu.Unlock()
	h.cancel()
	h.cleanup()
	e.log.Info("hosting stopped")
}

func (h *hostSession) cleanup() {
	h.mu.Lock()
	guests := make([]*guestConn, 0, len(h.guests))
	for _, g := range h.guests {
		guests = append(guests, g)
	}
	ep4, ep6, det, g := h.ep4, h.ep6, h.detector, h.gathered
	h.mu.Unlock()
	for _, x := range guests {
		_ = x.conn.CloseWithError(transport.CodeHostStopped, "host stopped")
	}
	if g != nil && g.Mapping != nil {
		_ = g.Mapping.Close()
	}
	if det != nil {
		_ = det.Close()
	}
	// Give CONNECTION_CLOSE frames a moment to leave before closing sockets.
	if len(guests) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	if ep4 != nil {
		_ = ep4.Close()
	}
	if ep6 != nil {
		_ = ep6.Close()
	}
	h.wg.Wait()
}

func (h *hostSession) state() HostState {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := HostState{
		Status: h.status, Error: h.err, Mode: h.mode, ManualPort: h.manualPort,
		LANDetection: h.detector != nil, TargetOK: h.targetOK,
		Guests: []GuestInfo{}, Pending: []GuestInfo{}, Punches: []PunchInfo{}, Worlds: []mclan.World{},
		BytesUp: h.stats.Up.Load(), BytesDown: h.stats.Down.Load(), Since: h.since,
		Approval: h.e.settings.Get().RequireApproval,
	}
	if h.detector != nil {
		s.Worlds = h.detector.Worlds()
	}
	if t, m := h.targetLocked(); t.IsValid() {
		s.Target, s.TargetMOTD = t.String(), m
		if h.mode == ModeAuto {
			s.TargetOK = true
		}
	}
	if h.ep4 != nil {
		s.UDPPort = int(h.ep4.Port())
	}
	if h.status == HostReady && h.invite != nil {
		s.Code, s.Link, s.Expires = h.code, joincode.Link(h.code), h.invite.Expires
	}
	if h.gathered != nil {
		s.Report = &h.gathered.Report
		o := connect.HostOutlook(s.Report)
		s.Outlook = &o
	}
	for _, g := range h.guests {
		s.Guests = append(s.Guests, g.info)
	}
	for _, p := range h.pending {
		s.Pending = append(s.Pending, p.info)
	}
	for _, p := range h.punches {
		s.Punches = append(s.Punches, *p)
	}
	return s
}

// codeError maps join-code decode errors to i18n keys.
func codeError(err error, fallback string) *UserError {
	key := fallback
	switch {
	case errors.Is(err, joincode.ErrEmpty):
		key = "err.code.empty"
	case errors.Is(err, joincode.ErrPrefix):
		key = "err.code.not_code"
	case errors.Is(err, joincode.ErrChecksum), errors.Is(err, joincode.ErrTruncated), errors.Is(err, joincode.ErrCharacters):
		key = "err.code.damaged"
	case errors.Is(err, joincode.ErrVersion):
		key = "err.code.newer_version"
	}
	return &UserError{Key: key, Status: http.StatusBadRequest, Detail: err.Error()}
}

func removeFile(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
