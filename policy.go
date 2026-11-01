// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// This file implements the client-bound request runtime policy stack.
//
// The stack lives on the [Client] instance (Client.policyStack), it is never a
// process-level singleton and it is never keyed by goroutine: every [Request]
// derived via [Client.R] resolves policy through Request.client, so two
// different [Client] values running on the same goroutine never share a stack
// top, and the same Client used from multiple goroutines consistently observes
// frames pushed for that Client.
//
// Goroutine identity is used for one purpose only: rejecting a frame push that
// happens too late inside the request execution that is already running on the
// caller's goroutine (for example, pushing skip-before from inside an
// OnBeforeRequest hook). It is never used to resolve effective policy.

// RetrySurface controls the retry surface of a single policy frame.
type RetrySurface int

const (
	// RetrySurfacePin keeps the Client/Request RetryCount and wait settings.
	RetrySurfacePin RetrySurface = iota

	// RetrySurfaceForceNoRetry makes the frame's sends non-retryable. A failed
	// send must not be retried. It does not touch RetryCount.
	RetrySurfaceForceNoRetry

	// RetrySurfaceForceRetryOnce makes the frame perform at least one more
	// observable attempt for a retryable error, even when RetryCount is 0.
	RetrySurfaceForceRetryOnce

	// RetrySurfaceRejectNonIdempotentRetry refuses to retry non-idempotent
	// methods for the frame, even when AllowNonIdempotentRetry is enabled.
	RetrySurfaceRejectNonIdempotentRetry
)

// RedirectAdmit controls redirect admission of a single policy frame.
type RedirectAdmit int

const (
	// RedirectAdmitPin keeps the configured [RedirectPolicy].
	RedirectAdmitPin RedirectAdmit = iota

	// RedirectAdmitRejectRedirect stops following on a 3xx response and
	// returns the redirect response without issuing the next hop.
	RedirectAdmitRejectRedirect

	// RedirectAdmitForceFollow follows at least one legal Location hop even
	// when the configured [RedirectPolicy] would have stopped.
	RedirectAdmitForceFollow
)

// MiddlewareGate controls middleware visibility of a single policy frame.
type MiddlewareGate int

const (
	// MiddlewareGatePin keeps the existing request/response middleware chains.
	MiddlewareGatePin MiddlewareGate = iota

	// MiddlewareGateSkipBefore suppresses user OnBeforeRequest hooks for the
	// frame's sends. Mandatory request preparation still runs.
	MiddlewareGateSkipBefore

	// MiddlewareGateSkipAfter suppresses user OnAfterResponse hooks for the
	// frame's sends, on both success and failure responses.
	MiddlewareGateSkipAfter
)

// TimeoutOverlay controls the effective timeout of a single policy frame.
type TimeoutOverlay int

const (
	// TimeoutOverlayPin keeps the Client/Request timeout.
	TimeoutOverlayPin TimeoutOverlay = iota

	// TimeoutOverlayFailFast applies a measurably shorter deadline and
	// surfaces the deadline error on timeout.
	TimeoutOverlayFailFast

	// TimeoutOverlayInheritOnly ignores a shorter timeout newly set on the
	// [Request] and only uses the Client timeout captured when the frame was
	// pushed.
	TimeoutOverlayInheritOnly
)

var (
	// ErrInvalidPolicyFrame is returned by [Client.PushPolicyFrame] when the
	// frame is malformed.
	ErrInvalidPolicyFrame = errors.New("resty: invalid policy frame")

	// ErrPolicyFrameTooLate is returned by [Client.PushPolicyFrame] when the
	// pushed frame would modify a dimension of a request already executing on
	// the caller's goroutine past the point where that dimension can take
	// effect. The in-flight send keeps its entry snapshot; the push is not
	// silently applied.
	ErrPolicyFrameTooLate = errors.New("resty: policy frame pushed too late for the in-flight request")
)

// PolicyFrame is one entry of the client policy stack. Unset dimensions are
// [RetrySurfacePin], [RedirectAdmitPin], [MiddlewareGatePin] and
// [TimeoutOverlayPin], so a frame only overrides the dimensions it sets and
// the other dimensions stay governed by frames below (or by the Client/Request
// flat fields when the stack is empty for them).
type PolicyFrame struct {
	// Retry selects the retry surface.
	Retry RetrySurface

	// Redirect selects redirect admission.
	Redirect RedirectAdmit

	// Middleware selects the middleware gate.
	Middleware MiddlewareGate

	// Timeout selects the timeout overlay.
	Timeout TimeoutOverlay

	// FailFastTimeout is the shorter deadline used with
	// [TimeoutOverlayFailFast]. It must be greater than zero.
	FailFastTimeout time.Duration

	// InheritTimeout is populated by [Client.PushPolicyFrame] with the Client
	// timeout present at push time; it is used with
	// [TimeoutOverlayInheritOnly].
	InheritTimeout time.Duration
}

func (f PolicyFrame) validate() error {
	if f.Retry < RetrySurfacePin || f.Retry > RetrySurfaceRejectNonIdempotentRetry {
		return fmt.Errorf("%w: unknown retry surface %d", ErrInvalidPolicyFrame, f.Retry)
	}
	if f.Redirect < RedirectAdmitPin || f.Redirect > RedirectAdmitForceFollow {
		return fmt.Errorf("%w: unknown redirect admit %d", ErrInvalidPolicyFrame, f.Redirect)
	}
	if f.Middleware < MiddlewareGatePin || f.Middleware > MiddlewareGateSkipAfter {
		return fmt.Errorf("%w: unknown middleware gate %d", ErrInvalidPolicyFrame, f.Middleware)
	}
	if f.Timeout < TimeoutOverlayPin || f.Timeout > TimeoutOverlayInheritOnly {
		return fmt.Errorf("%w: unknown timeout overlay %d", ErrInvalidPolicyFrame, f.Timeout)
	}
	if f.Timeout == TimeoutOverlayFailFast && f.FailFastTimeout <= 0 {
		return fmt.Errorf("%w: FailFastTimeout must be greater than zero", ErrInvalidPolicyFrame)
	}
	return nil
}

// PolicyScope is a pushed [PolicyFrame]. [PolicyScope.Pop] removes the frame,
// restoring the frame below.
type PolicyScope struct {
	client *Client
	seq    uint64
	popped bool
}

// Pop removes the pushed frame from its Client stack. A mismatched pop
// (another frame is on top) panics so unbalanced nesting fails loudly; a
// repeated Pop on the same scope is a no-op.
func (s *PolicyScope) Pop() {
	if s == nil || s.popped {
		return
	}
	s.client.popPolicyFrame(s)
	s.popped = true
}

// PushPolicyFrame pushes a [PolicyFrame] on this Client's runtime policy
// stack. Requests that enter [Request.Execute] after the push observe the
// frame; requests already in flight keep the snapshot they captured on entry.
//
// A frame that changes a dimension past the lifecycle boundary of the request
// currently executing on the caller's goroutine (for example pushing
// [MiddlewareGateSkipBefore] after OnBeforeRequest hooks started) is rejected
// with [ErrPolicyFrameTooLate].
func (c *Client) PushPolicyFrame(frame PolicyFrame) (*PolicyScope, error) {
	if err := frame.validate(); err != nil {
		return nil, err
	}

	// Read flat fields outside the policy lock to avoid nesting it with the
	// Client configuration lock.
	if frame.Timeout == TimeoutOverlayInheritOnly {
		frame.InheritTimeout = c.Timeout()
	}

	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	if err := c.checkLatePushLocked(frame, currentGoroutineID()); err != nil {
		return nil, err
	}

	c.policySeq++
	seq := c.policySeq
	c.policyStack = append(c.policyStack, policyFrameEntry{frame: frame, seq: seq})
	return &PolicyScope{client: c, seq: seq}, nil
}

// WithPolicyFrame pushes frame, runs fn, and always pops the frame when fn
// returns or panics (the panic is re-raised after the frame is removed).
func (c *Client) WithPolicyFrame(frame PolicyFrame, fn func()) error {
	scope, err := c.PushPolicyFrame(frame)
	if err != nil {
		return err
	}
	defer scope.Pop()
	if fn != nil {
		fn()
	}
	return nil
}

func (c *Client) popPolicyFrame(scope *PolicyScope) {
	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	n := len(c.policyStack)
	if n == 0 {
		panic("resty: policy frame pop on an empty stack")
	}
	top := c.policyStack[n-1]
	if top.seq != scope.seq {
		panic("resty: policy frame pop out of order; another frame is on top")
	}
	c.policyStack = c.policyStack[:n-1]
}

func (c *Client) checkLatePushLocked(frame PolicyFrame, goid int64) error {
	sends := c.activeSends[goid]
	if len(sends) == 0 {
		return nil
	}
	ss := sends[len(sends)-1]
	phase := ss.phase.Load()

	if frame.Retry != RetrySurfacePin && phase >= policyPhaseWire {
		return fmt.Errorf("%w: retry_surface cannot change after the request reached the transport",
			ErrPolicyFrameTooLate)
	}
	if frame.Timeout != TimeoutOverlayPin && phase >= policyPhaseWire {
		return fmt.Errorf("%w: timeout_overlay cannot change after the request reached the transport",
			ErrPolicyFrameTooLate)
	}
	if frame.Middleware == MiddlewareGateSkipBefore && phase >= policyPhaseBefore {
		return fmt.Errorf("%w: skip_before cannot apply once OnBeforeRequest hooks started",
			ErrPolicyFrameTooLate)
	}
	if frame.Middleware == MiddlewareGateSkipAfter && phase >= policyPhaseAfter {
		return fmt.Errorf("%w: skip_after cannot apply once OnAfterResponse hooks started",
			ErrPolicyFrameTooLate)
	}
	if frame.Redirect == RedirectAdmitRejectRedirect && ss.redirectFollowed.Load() {
		return fmt.Errorf("%w: reject_redirect cannot apply after a redirect hop was followed",
			ErrPolicyFrameTooLate)
	}
	return nil
}

// EffectivePolicy is the merged read-only view of the current Client policy
// stack top combined with the Client flat fields. With an empty stack every
// dimension is pinned and the view equals the Client flat configuration.
type EffectivePolicy struct {
	// RetrySurface is the effective retry surface.
	RetrySurface RetrySurface

	// RedirectAdmit is the effective redirect admission.
	RedirectAdmit RedirectAdmit

	// MiddlewareGate is the effective middleware gate. With stacked frames
	// carrying different skip directions this reports the top-most one; use
	// SkipBeforeHooks/SkipAfterHooks for the fully merged per-exit view.
	MiddlewareGate MiddlewareGate

	// SkipBeforeHooks reports whether any active frame suppresses
	// OnBeforeRequest hooks.
	SkipBeforeHooks bool

	// SkipAfterHooks reports whether any active frame suppresses
	// OnAfterResponse hooks.
	SkipAfterHooks bool

	// TimeoutOverlay is the effective timeout overlay.
	TimeoutOverlay TimeoutOverlay

	// RetryCount is the effective retry count after retry surface merging.
	RetryCount int

	// RetryWaitTime is the effective minimum retry wait.
	RetryWaitTime time.Duration

	// RetryMaxWaitTime is the effective maximum retry wait.
	RetryMaxWaitTime time.Duration

	// AllowNonIdempotentRetry reports whether non-idempotent methods may retry.
	AllowNonIdempotentRetry bool

	// Timeout is the effective timeout.
	Timeout time.Duration

	// FailFastTimeout carries the fail-fast deadline when applicable.
	FailFastTimeout time.Duration

	// InheritedTimeout carries the Client timeout captured at push time.
	InheritedTimeout time.Duration
}

// EffectivePolicy returns the policy currently effective on the Client,
// merging the stack top with the Client flat retry/redirect/middleware/timeout
// fields. It is a read interface; the send exits resolve their own dimensions
// independently from their entry snapshots.
func (c *Client) EffectivePolicy() EffectivePolicy {
	c.policyMu.Lock()
	frames := make([]PolicyFrame, len(c.policyStack))
	for i, e := range c.policyStack {
		frames[i] = e.frame
	}
	c.policyMu.Unlock()

	frame := resolvePolicyFrame(frames)

	var skipBefore, skipAfter bool
	for _, f := range frames {
		if f.Middleware == MiddlewareGateSkipBefore {
			skipBefore = true
		}
		if f.Middleware == MiddlewareGateSkipAfter {
			skipAfter = true
		}
	}

	view := EffectivePolicy{
		RetrySurface:            frame.Retry,
		RedirectAdmit:           frame.Redirect,
		MiddlewareGate:          frame.Middleware,
		SkipBeforeHooks:         skipBefore,
		SkipAfterHooks:          skipAfter,
		TimeoutOverlay:          frame.Timeout,
		RetryCount:              c.RetryCount(),
		RetryWaitTime:           c.RetryWaitTime(),
		RetryMaxWaitTime:        c.RetryMaxWaitTime(),
		AllowNonIdempotentRetry: c.IsRetryAllowNonIdempotent(),
		Timeout:                 c.Timeout(),
		FailFastTimeout:         frame.FailFastTimeout,
		InheritedTimeout:        frame.InheritTimeout,
	}

	switch frame.Retry {
	case RetrySurfaceForceNoRetry:
		view.RetryCount = 0
	case RetrySurfaceForceRetryOnce:
		if view.RetryCount < 1 {
			view.RetryCount = 1
		}
	case RetrySurfaceRejectNonIdempotentRetry:
		view.AllowNonIdempotentRetry = false
	}

	switch frame.Timeout {
	case TimeoutOverlayFailFast:
		view.Timeout = frame.FailFastTimeout
	case TimeoutOverlayInheritOnly:
		view.Timeout = frame.InheritTimeout
	}

	return view
}

// policyFrameEntry pairs a frame with its monotonic stack sequence number used
// to validate LIFO pops.
type policyFrameEntry struct {
	frame PolicyFrame
	seq   uint64
}

// Send lifecycle phases used by the late-push gate. They only advance.
const (
	// policyPhaseEntered: Execute entered, before any middleware ran.
	policyPhaseEntered int32 = iota

	// policyPhaseBefore: OnBeforeRequest chain execution started.
	policyPhaseBefore

	// policyPhaseWire: the request reached the transport (Client.Do entered).
	policyPhaseWire

	// policyPhaseAfter: OnAfterResponse chain execution started.
	policyPhaseAfter
)

type policySendKey struct{}

// policySend is the per-Execute entry snapshot. Every send exit (retry loop,
// redirect dispatch, middleware chains, timeout overlay) reads this snapshot
// through its own dimension resolver, never a shared all-in-one boolean.
type policySend struct {
	goid int64

	// frames is the policy stack as it existed at Execute entry.
	frames []PolicyFrame

	// policies is the redirect policy chain as it existed at Execute entry.
	policies []RedirectPolicy

	phase            atomic.Int32
	redirectFollowed atomic.Bool
}

func (c *Client) beginPolicySend() *policySend {
	c.lock.RLock()
	policies := slicesClonePolicies(c.redirectPolicies)
	c.lock.RUnlock()

	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	ss := &policySend{
		goid:     currentGoroutineID(),
		policies: policies,
		frames:   make([]PolicyFrame, len(c.policyStack)),
	}
	for i, e := range c.policyStack {
		ss.frames[i] = e.frame
	}
	if c.activeSends == nil {
		c.activeSends = make(map[int64][]*policySend)
	}
	c.activeSends[ss.goid] = append(c.activeSends[ss.goid], ss)
	return ss
}

func (c *Client) endPolicySend(ss *policySend) {
	c.policyMu.Lock()
	defer c.policyMu.Unlock()

	stack := c.activeSends[ss.goid]
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == ss {
			c.activeSends[ss.goid] = append(stack[:i], stack[i+1:]...)
			break
		}
	}
	if len(c.activeSends[ss.goid]) == 0 {
		delete(c.activeSends, ss.goid)
	}
}

func (ss *policySend) setPhase(phase int32) {
	if ss == nil {
		return
	}
	for {
		current := ss.phase.Load()
		if current >= phase || ss.phase.CompareAndSwap(current, phase) {
			return
		}
	}
}

// retrySurface is read by the retry loop in [Request.Execute].
func (ss *policySend) retrySurface() RetrySurface {
	if ss == nil {
		return RetrySurfacePin
	}
	return resolvePolicyFrame(ss.frames).Retry
}

// redirectAdmit is read by the redirect follow path.
func (ss *policySend) redirectAdmit() RedirectAdmit {
	if ss == nil {
		return RedirectAdmitPin
	}
	return resolvePolicyFrame(ss.frames).Redirect
}

// middlewareSkipBefore is read independently at the OnBeforeRequest exit.
// Suppression composes across stacked frames: any frame on the stack that
// carries [MiddlewareGateSkipBefore] hides before hooks for the send, while a
// frame carrying [MiddlewareGateSkipAfter] does not mask it.
func (ss *policySend) middlewareSkipBefore() bool {
	if ss == nil {
		return false
	}
	for i := len(ss.frames) - 1; i >= 0; i-- {
		if ss.frames[i].Middleware == MiddlewareGateSkipBefore {
			return true
		}
	}
	return false
}

// middlewareSkipAfter is read independently at the OnAfterResponse exit.
func (ss *policySend) middlewareSkipAfter() bool {
	if ss == nil {
		return false
	}
	for i := len(ss.frames) - 1; i >= 0; i-- {
		if ss.frames[i].Middleware == MiddlewareGateSkipAfter {
			return true
		}
	}
	return false
}

// timeoutView is read by the per-attempt timeout overlay.
func (ss *policySend) timeoutView() (TimeoutOverlay, time.Duration, time.Duration) {
	if ss == nil {
		return TimeoutOverlayPin, 0, 0
	}
	f := resolvePolicyFrame(ss.frames)
	return f.Timeout, f.FailFastTimeout, f.InheritTimeout
}

// resolvePolicyFrame merges a frame snapshot dimension by dimension: for each
// dimension the top-most frame that sets a non-pin value wins; a pin frame
// leaves the dimension to the frame below it, and when no frame sets it the
// zero value (pin) is returned so the Client/Request flat field applies.
func resolvePolicyFrame(frames []PolicyFrame) PolicyFrame {
	var merged PolicyFrame
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		if merged.Retry == RetrySurfacePin && f.Retry != RetrySurfacePin {
			merged.Retry = f.Retry
		}
		if merged.Redirect == RedirectAdmitPin && f.Redirect != RedirectAdmitPin {
			merged.Redirect = f.Redirect
		}
		if merged.Middleware == MiddlewareGatePin && f.Middleware != MiddlewareGatePin {
			merged.Middleware = f.Middleware
		}
		if merged.Timeout == TimeoutOverlayPin && f.Timeout != TimeoutOverlayPin {
			merged.Timeout = f.Timeout
			merged.FailFastTimeout = f.FailFastTimeout
			merged.InheritTimeout = f.InheritTimeout
		}
		if merged.Retry != RetrySurfacePin &&
			merged.Redirect != RedirectAdmitPin &&
			merged.Middleware != MiddlewareGatePin &&
			merged.Timeout != TimeoutOverlayPin {
			break
		}
	}
	return merged
}

func slicesClonePolicies(in []RedirectPolicy) []RedirectPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make([]RedirectPolicy, len(in))
	copy(out, in)
	return out
}

// isBuiltinRequestMiddleware reports whether f is Resty's built-in request
// preparation middleware. Function values are not comparable, so identity is
// established by code pointer.
func isBuiltinRequestMiddleware(f RequestMiddleware) bool {
	return reflect.ValueOf(f).Pointer() == reflect.ValueOf(MiddlewareRequestCreate).Pointer()
}

// isBuiltinResponseMiddleware reports whether f is one of Resty's built-in
// response middlewares (auto parse, save to file).
func isBuiltinResponseMiddleware(f ResponseMiddleware) bool {
	p := reflect.ValueOf(f).Pointer()
	return p == reflect.ValueOf(MiddlewareResponseAutoParse).Pointer() ||
		p == reflect.ValueOf(MiddlewareResponseSaveToFile).Pointer()
}

// defaultMaxRedirects mirrors net/http's own limit, which only applies when
// http.Client.CheckRedirect is nil. Resty always installs its dispatcher so
// frames can intervene per send, so the no-policy case reproduces the default.
const defaultMaxRedirects = 10

// errDefaultMaxRedirects matches net/http's default redirect error exactly, so
// transport-error retry classification keeps treating it as non-retryable.
var errDefaultMaxRedirects = errors.New("stopped after 10 redirects")

// redirectCheckRedirect is the permanent CheckRedirect dispatcher. It reads
// the redirect dimension of the send snapshot carried by the request context;
// it never swaps the configured [RedirectPolicy] per send.
func (c *Client) redirectCheckRedirect(req *http.Request, via []*http.Request) error {
	var policies []RedirectPolicy
	admit := RedirectAdmitPin
	var ss *policySend

	if v := req.Context().Value(policySendKey{}); v != nil {
		ss, _ = v.(*policySend)
	}
	if ss != nil {
		policies = ss.policies
		admit = ss.redirectAdmit()
	} else {
		c.lock.RLock()
		policies = slicesClonePolicies(c.redirectPolicies)
		c.lock.RUnlock()
	}

	// reject_redirect: do not issue the next hop; net/http returns the 3xx
	// response itself when ErrUseLastResponse is used.
	if admit == RedirectAdmitRejectRedirect {
		return http.ErrUseLastResponse
	}

	// No configured policy: reproduce net/http's default 10-hop behavior.
	if len(policies) == 0 {
		if len(via) >= defaultMaxRedirects {
			return errDefaultMaxRedirects
		}
		if ss != nil {
			ss.redirectFollowed.Store(true)
		}
		return nil
	}

	var policyErr error
	for _, p := range policies {
		if err := p.Apply(req, via); err != nil {
			policyErr = err
			break
		}
	}

	// force_follow: the first legal Location hop must be followed even if the
	// configured policy would stop here.
	if policyErr != nil {
		if admit == RedirectAdmitForceFollow && len(via) == 1 {
			if ss != nil {
				ss.redirectFollowed.Store(true)
			}
			return nil
		}
		return policyErr
	}

	if ss != nil {
		ss.redirectFollowed.Store(true)
	}
	return nil
}

// currentGoroutineID parses the goroutine id from runtime.Stack. It is used
// only to associate a push with the send currently running on the same
// goroutine for late-push rejection.
func currentGoroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	const prefix = "goroutine "
	b := buf[len(prefix):n]
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		return -1
	}
	id, err := strconv.ParseInt(string(b[:i]), 10, 64)
	if err != nil {
		return -1
	}
	return id
}

// policySendFromContext exposes the send snapshot stored on a context; used
// by tests and internal plumbing.
func policySendFromContext(ctx context.Context) *policySend {
	if v := ctx.Value(policySendKey{}); v != nil {
		if ss, ok := v.(*policySend); ok {
			return ss
		}
	}
	return nil
}
