// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Test helpers
//_______________________________________________________________________

// tempNetErr is a retryable temporary network error (net.Error shaped).
type tempNetErr struct{}

func (tempNetErr) Error() string   { return "temporary transport failure" }
func (tempNetErr) Timeout() bool   { return false }
func (tempNetErr) Temporary() bool { return true }

// flakyRoundTripper fails the first failUntil attempts with a retryable
// temporary transport error (or serves statusCode when it is non-zero) and
// then serves a synthetic 200. It records the methods and paths that actually
// reached the transport.
type flakyRoundTripper struct {
	count      atomic.Int32
	failUntil  int32
	statusCode int
	methods    []string
	paths      []string
	mu         sync.Mutex
}

func (f *flakyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	n := f.count.Add(1)
	f.mu.Lock()
	f.methods = append(f.methods, req.Method)
	f.paths = append(f.paths, req.URL.Path)
	f.mu.Unlock()

	if n <= f.failUntil {
		if f.statusCode != 0 {
			return &http.Response{
				StatusCode: f.statusCode,
				Status:     fmt.Sprintf("%d status", f.statusCode),
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("failure")),
				Request:    req,
			}, nil
		}
		return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: tempNetErr{}}
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("ok")),
		ContentLength: 2,
		Request:       req,
	}, nil
}

func (f *flakyRoundTripper) attempts() int { return int(f.count.Load()) }

func (f *flakyRoundTripper) calls() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...), append([]string(nil), f.paths...)
}

// policyRedirectServer serves /go -> /hop -> /target and counts hits.
func policyRedirectServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var targetHits atomic.Int32
	var hopHits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/hop", http.StatusFound)
	})
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		hopHits.Add(1)
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("target"))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("slow-ok"))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, &targetHits
}

// invokers send through both documented exits derived from Client.R: the Get
// verb and Execute. Every exit goes through the same Request.Execute send
// path and must read the same Client stack.
func getInvokers() map[string]func(*Client, string) (*Response, error) {
	return map[string]func(*Client, string) (*Response, error){
		"Get": func(c *Client, u string) (*Response, error) {
			return c.R().Get(u)
		},
		"Execute": func(c *Client, u string) (*Response, error) {
			return c.R().Execute(MethodGet, u)
		},
	}
}

func postInvokers() map[string]func(*Client, string) (*Response, error) {
	return map[string]func(*Client, string) (*Response, error){
		"Post": func(c *Client, u string) (*Response, error) {
			return c.R().Post(u)
		},
		"ExecutePost": func(c *Client, u string) (*Response, error) {
			return c.R().Execute(MethodPost, u)
		},
	}
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Stack mechanics
//_______________________________________________________________________

func TestPolicyEmptyStackIsPinned(t *testing.T) {
	c := dcnl().SetRetryCount(2).SetTimeout(time.Second)
	view := c.EffectivePolicy()

	assertEqual(t, RetrySurfacePin, view.RetrySurface)
	assertEqual(t, RedirectAdmitPin, view.RedirectAdmit)
	assertEqual(t, MiddlewareGatePin, view.MiddlewareGate)
	assertEqual(t, TimeoutOverlayPin, view.TimeoutOverlay)
	// Empty stack merges straight to the flat Client fields.
	assertEqual(t, 2, view.RetryCount)
	assertEqual(t, time.Second, view.Timeout)
	assertEqual(t, false, view.AllowNonIdempotentRetry)
}

func TestPolicyPushPopRestoresOuterFrame(t *testing.T) {
	c := dcnl().SetRetryCount(5)

	outer, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	assertNil(t, err)
	assertEqual(t, 0, c.EffectivePolicy().RetryCount)

	inner, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipAfter})
	assertNil(t, err)
	view := c.EffectivePolicy()
	assertEqual(t, RetrySurfaceForceNoRetry, view.RetrySurface)
	assertEqual(t, MiddlewareGateSkipAfter, view.MiddlewareGate)

	// Pop returns to the outer frame, never to a process singleton.
	inner.Pop()
	view = c.EffectivePolicy()
	assertEqual(t, RetrySurfaceForceNoRetry, view.RetrySurface)
	assertEqual(t, MiddlewareGatePin, view.MiddlewareGate)

	outer.Pop()
	view = c.EffectivePolicy()
	assertEqual(t, RetrySurfacePin, view.RetrySurface)
	assertEqual(t, 5, view.RetryCount)
}

func TestPolicyNestedFrameInnerPopRevealsOuter(t *testing.T) {
	c := dcnl()
	var beforeCalls, afterCalls atomic.Int32
	c.AddRequestMiddleware(func(*Client, *Request) error {
		beforeCalls.Add(1)
		return nil
	})
	c.AddResponseMiddleware(func(*Client, *Response) error {
		afterCalls.Add(1)
		return nil
	})

	outer, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipBefore})
	assertNil(t, err)
	inner, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipAfter})
	assertNil(t, err)

	tr := &flakyRoundTripper{}
	_, _ = sendOnTransport(c, tr)
	assertEqual(t, int32(0), beforeCalls.Load())
	assertEqual(t, int32(0), afterCalls.Load())

	// Pop the inner frame: outer skip_before becomes visible again.
	inner.Pop()
	_, _ = sendOnTransport(c, tr)
	assertEqual(t, int32(0), beforeCalls.Load())
	assertEqual(t, int32(1), afterCalls.Load())

	outer.Pop()
	_, _ = sendOnTransport(c, tr)
	assertEqual(t, int32(1), beforeCalls.Load())
	assertEqual(t, int32(2), afterCalls.Load())
}

func sendOnTransport(c *Client, tr http.RoundTripper) (*Response, error) {
	c.SetTransport(tr)
	return c.R().Get("http://policy.example/ping")
}

func TestPolicyInvalidFramesRejected(t *testing.T) {
	c := dcnl()

	if _, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurface(99)}); !errors.Is(err, ErrInvalidPolicyFrame) {
		t.Fatalf("expected ErrInvalidPolicyFrame for bad retry surface, got %v", err)
	}
	if _, err := c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmit(42)}); !errors.Is(err, ErrInvalidPolicyFrame) {
		t.Fatalf("expected ErrInvalidPolicyFrame for bad redirect admit, got %v", err)
	}
	if _, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGate(7)}); !errors.Is(err, ErrInvalidPolicyFrame) {
		t.Fatalf("expected ErrInvalidPolicyFrame for bad middleware gate, got %v", err)
	}
	if _, err := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlay(9)}); !errors.Is(err, ErrInvalidPolicyFrame) {
		t.Fatalf("expected ErrInvalidPolicyFrame for bad timeout overlay, got %v", err)
	}
	if _, err := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayFailFast}); !errors.Is(err, ErrInvalidPolicyFrame) {
		t.Fatalf("expected ErrInvalidPolicyFrame for zero fail-fast deadline, got %v", err)
	}
}

func TestPolicyOutOfOrderAndRepeatedPop(t *testing.T) {
	c := dcnl()
	a, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	assertNil(t, err)
	b, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceRetryOnce})
	assertNil(t, err)

	// Popping a non-top scope panics.
	func() {
		defer func() {
			if rec := recover(); rec == nil {
				t.Fatalf("expected panic on out-of-order pop")
			}
		}()
		a.Pop()
	}()

	b.Pop()
	a.Pop()
	// Repeated pops are no-ops.
	b.Pop()
	a.Pop()
	assertEqual(t, RetrySurfacePin, c.EffectivePolicy().RetrySurface)
}

func TestPolicyWithFrameAlwaysPopsOnPanic(t *testing.T) {
	c := dcnl()

	func() {
		defer func() {
			if rec := recover(); rec == nil {
				t.Fatalf("expected panic to propagate")
			}
		}()
		_ = c.WithPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry}, func() {
			assertEqual(t, RetrySurfaceForceNoRetry, c.EffectivePolicy().RetrySurface)
			panic("boom")
		})
	}()

	// Exceptional path popped the frame cleanly.
	assertEqual(t, RetrySurfacePin, c.EffectivePolicy().RetrySurface)
}

func TestPolicyFlatFieldsNeverMutated(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 5}
	c := dcnl().
		SetTransport(tr).
		SetRetryCount(3).
		SetTimeout(2 * time.Second).
		SetRetryAllowNonIdempotent(true).
		SetRedirectPolicy(RedirectNoPolicy())
	policiesBefore := c.RedirectPoliciesCount()

	scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	assertNil(t, err)

	r := c.R().SetRetryCount(3).SetTimeout(2 * time.Second)
	_, _ = r.Get("http://policy.example/x")
	scope.Pop()

	// The frame never impersonated itself by rewriting flat fields.
	assertEqual(t, 3, c.RetryCount())
	assertEqual(t, 3, r.RetryCount)
	assertEqual(t, 2*time.Second, c.Timeout())
	assertEqual(t, 2*time.Second, r.Timeout)
	assertEqual(t, true, c.IsRetryAllowNonIdempotent())
	assertEqual(t, policiesBefore, c.RedirectPoliciesCount())
	assertEqual(t, 1, tr.attempts())
}

// RedirectPoliciesCount is a test-only count helper.
func (c *Client) RedirectPoliciesCount() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return len(c.redirectPolicies)
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// retry_surface exit (Get and Execute)
//_______________________________________________________________________

func TestPolicyRetryForceNoRetry(t *testing.T) {
	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			tr := &flakyRoundTripper{failUntil: 5}
			c := dcnl().SetTransport(tr).SetRetryCount(3).
				SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

			scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
			assertNil(t, err)
			_, sendErr := invoke(c, "http://policy.example/no-retry")
			scope.Pop()

			assertNotNil(t, sendErr)
			assertEqual(t, 1, tr.attempts(), "frame must not retry")
			// Next send outside the frame retries again.
			_, _ = invoke(c, "http://policy.example/plain")
			if tr.attempts() == 1 {
				t.Fatalf("expected retries after pop, got only %d attempts", tr.attempts())
			}
		})
	}
}

func TestPolicyRetryForceRetryOnce(t *testing.T) {
	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			tr := &flakyRoundTripper{failUntil: 1}
			c := dcnl().SetTransport(tr).
				SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)
			// RetryCount stays 0; the frame must force one observable retry.
			assertEqual(t, 0, c.R().RetryCount)

			scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceRetryOnce})
			assertNil(t, err)
			resp, sendErr := invoke(c, "http://policy.example/once")
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, http.StatusOK, resp.StatusCode())
			assertEqual(t, 2, resp.Request.Attempt, "one forced observable retry expected")
		})
	}
}

func TestPolicyRetryForceRetryOnceNotTriggeredOnSuccess(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 0}
	c := dcnl().SetTransport(tr)
	scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceRetryOnce})
	assertNil(t, err)
	resp, sendErr := c.R().Get("http://policy.example/ok")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, 1, resp.Request.Attempt)
}

func TestPolicyRejectNonIdempotentRetry(t *testing.T) {
	for name, invoke := range postInvokers() {
		t.Run(name, func(t *testing.T) {
			tr := &flakyRoundTripper{failUntil: 5}
			c := dcnl().SetTransport(tr).
				SetRetryCount(3).SetRetryAllowNonIdempotent(true).
				SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

			scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceRejectNonIdempotentRetry})
			assertNil(t, err)
			_, sendErr := invoke(c, "http://policy.example/post")
			scope.Pop()

			assertNotNil(t, sendErr)
			assertEqual(t, 1, tr.attempts(), "non-idempotent POST must not retry under frame")
			methods, _ := tr.calls()
			assertEqual(t, MethodPost, methods[0])
		})
	}
}

func TestPolicyRejectNonIdempotentRetryKeepsIdempotentVerbs(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 1}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceRejectNonIdempotentRetry})
	assertNil(t, err)
	resp, sendErr := c.R().Get("http://policy.example/get")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, 2, resp.Request.Attempt, "idempotent GET still retries under the frame")
}

func TestPolicyPinKeepsConfiguredRetrySurface(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 2}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)
	scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfacePin})
	assertNil(t, err)
	resp, sendErr := c.R().Get("http://policy.example/pin")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, 3, resp.Request.Attempt)
}

func TestPolicyEffectiveViewMerge(t *testing.T) {
	c := dcnl().SetRetryCount(0).SetRetryAllowNonIdempotent(true).SetTimeout(time.Second)

	s1, _ := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceRetryOnce})
	v := c.EffectivePolicy()
	assertEqual(t, 1, v.RetryCount)
	assertEqual(t, true, v.AllowNonIdempotentRetry)
	s1.Pop()

	s2, _ := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceRejectNonIdempotentRetry})
	assertEqual(t, false, c.EffectivePolicy().AllowNonIdempotentRetry)
	s2.Pop()

	s3, _ := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayFailFast, FailFastTimeout: 5 * time.Millisecond})
	v = c.EffectivePolicy()
	assertEqual(t, 5*time.Millisecond, v.Timeout)
	assertEqual(t, 5*time.Millisecond, v.FailFastTimeout)
	s3.Pop()

	s4, _ := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayInheritOnly})
	assertEqual(t, time.Second, c.EffectivePolicy().InheritedTimeout)
	s4.Pop()
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// redirect_admit exit (Get and Execute)
//_______________________________________________________________________

func TestPolicyRejectRedirect(t *testing.T) {
	ts, targetHits := policyRedirectServer(t)

	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			targetHits.Store(0)
			c := dcnl()
			scope, err := c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmitRejectRedirect})
			assertNil(t, err)
			resp, sendErr := invoke(c, ts.URL+"/go")
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, http.StatusFound, resp.StatusCode(), "3xx must be returned without following")
			assertEqual(t, int32(0), targetHits.Load(), "no next hop may be issued")
		})
	}
}

func TestPolicyForceFollow(t *testing.T) {
	ts, targetHits := policyRedirectServer(t)

	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			targetHits.Store(0)
			c := dcnl().SetRedirectPolicy(RedirectNoPolicy())

			// Without a frame the policy stops: 302, no target hit.
			resp, sendErr := invoke(c, ts.URL+"/one")
			assertNil(t, sendErr)
			assertEqual(t, http.StatusFound, resp.StatusCode())
			assertEqual(t, int32(0), targetHits.Load())

			// force_follow overrides the stop and observes at least one hop.
			scope, err := c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmitForceFollow})
			assertNil(t, err)
			resp, sendErr = invoke(c, ts.URL+"/one")
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, http.StatusOK, resp.StatusCode())
			assertEqual(t, "target", resp.String())
			assertEqual(t, int32(1), targetHits.Load(), "legal Location must be followed")
		})
	}
}

func TestPolicyRedirectPinKeepsDefaultFollowing(t *testing.T) {
	ts, targetHits := policyRedirectServer(t)
	c := dcnl()
	scope, err := c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmitPin})
	assertNil(t, err)
	resp, sendErr := c.R().Get(ts.URL + "/go")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, int32(1), targetHits.Load())
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// middleware_gate exit (Get and Execute)
//_______________________________________________________________________

func TestPolicySkipBefore(t *testing.T) {
	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			tr := &flakyRoundTripper{}
			var hookCalls atomic.Int32
			c := dcnl().SetTransport(tr).AddRequestMiddleware(func(*Client, *Request) error {
				hookCalls.Add(1)
				return nil
			})

			scope, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipBefore})
			assertNil(t, err)
			resp, sendErr := invoke(c, "http://policy.example/skip-before")
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, http.StatusOK, resp.StatusCode(), "request must still be prepared and sent")
			assertEqual(t, int32(0), hookCalls.Load(), "OnBeforeRequest hooks must not run")
			assertEqual(t, 1, tr.attempts())

			// Pin behavior restored.
			_, _ = invoke(c, "http://policy.example/plain")
			assertEqual(t, int32(1), hookCalls.Load())
		})
	}
}

func TestPolicySkipAfter(t *testing.T) {
	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			tr := &flakyRoundTripper{}
			var hookCalls atomic.Int32
			c := dcnl().SetTransport(tr).AddResponseMiddleware(func(*Client, *Response) error {
				hookCalls.Add(1)
				return nil
			})

			scope, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipAfter})
			assertNil(t, err)
			resp, sendErr := invoke(c, "http://policy.example/skip-after")
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, int32(0), hookCalls.Load(), "OnAfterResponse hooks must not run on success")
			// Built-in response processing still consumed the body.
			assertEqual(t, "ok", resp.String())

			_, _ = invoke(c, "http://policy.example/plain")
			assertEqual(t, int32(1), hookCalls.Load())
		})
	}
}

func TestPolicySkipAfterAlsoAppliesOnFailure(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 10, statusCode: http.StatusInternalServerError}
	var hookCalls atomic.Int32
	c := dcnl().SetTransport(tr).AddResponseMiddleware(func(*Client, *Response) error {
		hookCalls.Add(1)
		return nil
	})

	scope, err := c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipAfter})
	assertNil(t, err)
	resp, sendErr := c.R().Get("http://policy.example/fail")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, http.StatusInternalServerError, resp.StatusCode())
	assertEqual(t, int32(0), hookCalls.Load(), "OnAfterResponse hooks must not run on failure either")
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// timeout_overlay exit (Get and Execute)
//_______________________________________________________________________

func TestPolicyTimeoutFailFast(t *testing.T) {
	ts, _ := policyRedirectServer(t)

	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			c := dcnl().SetTimeout(30 * time.Second)
			scope, err := c.PushPolicyFrame(PolicyFrame{
				Timeout:         TimeoutOverlayFailFast,
				FailFastTimeout: 40 * time.Millisecond,
			})
			assertNil(t, err)

			start := time.Now()
			_, sendErr := invoke(c, ts.URL+"/slow")
			elapsed := time.Since(start)
			scope.Pop()

			if !errors.Is(sendErr, context.DeadlineExceeded) {
				t.Fatalf("expected deadline exceeded, got %v", sendErr)
			}
			if elapsed >= time.Second {
				t.Fatalf("fail-fast deadline not used, elapsed %v", elapsed)
			}
		})
	}
}

func TestPolicyTimeoutInheritOnly(t *testing.T) {
	ts, _ := policyRedirectServer(t)

	for name, invoke := range getInvokers() {
		t.Run(name, func(t *testing.T) {
			c := dcnl().SetTimeout(3 * time.Second)
			scope, err := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayInheritOnly})
			assertNil(t, err)

			start := time.Now()
			resp, sendErr := invoke(c, ts.URL+"/slow")
			elapsed := time.Since(start)
			scope.Pop()

			assertNil(t, sendErr)
			assertEqual(t, http.StatusOK, resp.StatusCode())
			if elapsed < 200*time.Millisecond {
				t.Fatalf("short request timeout should have been ignored, elapsed %v", elapsed)
			}
		})
	}
}

func TestPolicyTimeoutInheritOnlyIgnoresRequestShorterTimeout(t *testing.T) {
	ts, _ := policyRedirectServer(t)
	c := dcnl().SetTimeout(3 * time.Second)
	scope, err := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayInheritOnly})
	assertNil(t, err)

	// Newly set shorter request timeout must be ignored by this frame.
	r := c.R().SetTimeout(30 * time.Millisecond)
	resp, sendErr := r.Get(ts.URL + "/slow")
	scope.Pop()

	assertNil(t, sendErr)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, 30*time.Millisecond, r.Timeout, "flat request timeout must not be rewritten")
}

func TestPolicyTimeoutPinUsesRequestTimeout(t *testing.T) {
	ts, _ := policyRedirectServer(t)
	c := dcnl()
	scope, err := c.PushPolicyFrame(PolicyFrame{Timeout: TimeoutOverlayPin})
	assertNil(t, err)
	_, sendErr := c.R().SetTimeout(30 * time.Millisecond).Get(ts.URL + "/slow")
	scope.Pop()

	if !errors.Is(sendErr, context.DeadlineExceeded) {
		t.Fatalf("expected request timeout to apply under pin, got %v", sendErr)
	}
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Late push rejection at lifecycle boundaries
//_______________________________________________________________________

func TestPolicyLatePushSkipBeforeRejected(t *testing.T) {
	c := dcnl()
	var pushErr error
	c.AddRequestMiddleware(func(c *Client, _ *Request) error {
		_, pushErr = c.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipBefore})
		return nil
	})

	_, _ = c.R().Get("http://policy.example/late-before")
	if !errors.Is(pushErr, ErrPolicyFrameTooLate) {
		t.Fatalf("expected ErrPolicyFrameTooLate, got %v", pushErr)
	}
}

func TestPolicyLatePushForceNoRetryInRetryHookRejected(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 3}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	var pushErr error
	c.AddRetryHooks(func(_ *Response, _ error) {
		_, pushErr = c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	})

	_, _ = c.R().Get("http://policy.example/late-retry")
	if !errors.Is(pushErr, ErrPolicyFrameTooLate) {
		t.Fatalf("expected ErrPolicyFrameTooLate, got %v", pushErr)
	}
}

func TestPolicyLatePushFailFastAfterWireRejected(t *testing.T) {
	tr := &flakyRoundTripper{}
	c := dcnl().SetTransport(tr)

	var pushErr error
	c.AddResponseMiddleware(func(c *Client, _ *Response) error {
		_, pushErr = c.PushPolicyFrame(PolicyFrame{
			Timeout:         TimeoutOverlayFailFast,
			FailFastTimeout: time.Millisecond,
		})
		return nil
	})

	_, _ = c.R().Get("http://policy.example/late-timeout")
	if !errors.Is(pushErr, ErrPolicyFrameTooLate) {
		t.Fatalf("expected ErrPolicyFrameTooLate, got %v", pushErr)
	}
}

func TestPolicyLatePushRejectRedirectAfterFollowRejected(t *testing.T) {
	ts, _ := policyRedirectServer(t)
	c := dcnl()
	var pushErr error
	c.SetRedirectPolicy(RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
		checkHostAndAddHeaders(req, via)
		if len(via) >= 2 {
			// A hop was already followed: rejecting now is too late.
			_, pushErr = c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmitRejectRedirect})
		}
		return nil
	}))

	resp, sendErr := c.R().Get(ts.URL + "/go")
	assertNil(t, sendErr)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	if !errors.Is(pushErr, ErrPolicyFrameTooLate) {
		t.Fatalf("expected ErrPolicyFrameTooLate, got %v", pushErr)
	}
}

func TestPolicyLatePushDoesNotSilentlyChangeInFlightSend(t *testing.T) {
	// A push rejected at a boundary must leave the in-flight send on its
	// entry snapshot: the pin send retries normally even though a force-no-
	// retry push was attempted from a hook.
	tr := &flakyRoundTripper{failUntil: 2}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	var pushErr error
	c.AddRetryHooks(func(_ *Response, _ error) {
		if pushErr == nil {
			_, pushErr = c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
		}
	})

	resp, _ := c.R().Get("http://policy.example/snapshot")
	if !errors.Is(pushErr, ErrPolicyFrameTooLate) {
		t.Fatalf("expected rejection, got %v", pushErr)
	}
	assertEqual(t, 3, resp.Request.Attempt, "entry snapshot must remain in force")
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Client instance isolation (same goroutine and concurrent)
//_______________________________________________________________________

func TestPolicyTwoClientsSameGoroutineDoNotShareStack(t *testing.T) {
	trA := &flakyRoundTripper{failUntil: 5}
	trB := &flakyRoundTripper{failUntil: 3}
	cA := dcnl().SetTransport(trA).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)
	cB := dcnl().SetTransport(trB).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	scope, err := cA.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	assertNil(t, err)

	// Same goroutine, second Client must not see cA's frame.
	assertEqual(t, RetrySurfacePin, cB.EffectivePolicy().RetrySurface)
	_, errA := cA.R().Get("http://a.example/x")
	respB, errB := cB.R().Get("http://b.example/x")

	scope.Pop()

	assertNotNil(t, errA)
	assertNil(t, errB)
	assertEqual(t, 1, trA.attempts(), "cA frame must stop retries on cA")
	if trB.attempts() <= 1 {
		t.Fatalf("cB must keep retrying with its own empty stack, got %d attempts", trB.attempts())
	}
	assertEqual(t, 4, respB.Request.Attempt)
}

func TestPolicyTwoClientsMiddlewareIsolationSameGoroutine(t *testing.T) {
	var aHooks, bHooks atomic.Int32
	cA := dcnl().SetTransport(&flakyRoundTripper{}).
		AddResponseMiddleware(func(*Client, *Response) error { aHooks.Add(1); return nil })
	cB := dcnl().SetTransport(&flakyRoundTripper{}).
		AddResponseMiddleware(func(*Client, *Response) error { bHooks.Add(1); return nil })

	scope, err := cA.PushPolicyFrame(PolicyFrame{Middleware: MiddlewareGateSkipAfter})
	assertNil(t, err)
	_, _ = cA.R().Get("http://a.example/hook")
	_, _ = cB.R().Get("http://b.example/hook")
	scope.Pop()

	assertEqual(t, int32(0), aHooks.Load())
	assertEqual(t, int32(1), bHooks.Load(), "cB hook chain must be invisible to cA frame")
}

func TestPolicyTwoClientsConcurrentDifferentFrames(t *testing.T) {
	const goroutines = 24

	// cA pushes force_no_retry with RetryCount=3 on an always-failing
	// transport; cB concurrently pushes force_retry_once with RetryCount=0
	// against a server that fails each unique path once (500). Different
	// retry_surface values on two real, shared Clients must never cross.
	var bHits sync.Map
	bMux := http.NewServeMux()
	bMux.HandleFunc("/b/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := bHits.LoadOrStore(r.URL.Path, new(atomic.Int32))
		if n.(*atomic.Int32).Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	bServer := httptest.NewServer(bMux)
	defer bServer.Close()

	cA := dcnl().
		SetTransport(&flakyRoundTripper{failUntil: 1 << 30}).
		SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)
	cB := dcnl().
		SetRetryCount(0).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond).
		AddRetryConditions(RetryConditionStatus5XX)

	// Serialize push/send/pop per client so the shared LIFO stack stays
	// balanced; the two client mutexes are independent so cA and cB run
	// concurrently and exercise the separate stacks under -race.
	var muA, muB sync.Mutex
	var aAttempts atomic.Int32

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*2)
	for i := 0; i < goroutines; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			muA.Lock()
			defer muA.Unlock()
			scope, err := cA.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
			if err != nil {
				errCh <- fmt.Errorf("cA push: %w", err)
				return
			}
			resp, sendErr := cA.R().Get("http://a.example/concurrent")
			scope.Pop()
			if sendErr == nil || resp.Request.Attempt != 1 {
				errCh <- fmt.Errorf("cA: expected 1 attempt with error, got attempts=%d err=%v",
					resp.Request.Attempt, sendErr)
			}
			aAttempts.Add(1)
		}()

		go func(i int) {
			defer wg.Done()
			muB.Lock()
			defer muB.Unlock()
			scope, err := cB.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceRetryOnce})
			if err != nil {
				errCh <- fmt.Errorf("cB push: %w", err)
				return
			}
			resp, sendErr := cB.R().Get(fmt.Sprintf("%s/b/%d", bServer.URL, i))
			scope.Pop()
			if sendErr != nil || resp.Request.Attempt != 2 {
				errCh <- fmt.Errorf("cB: expected 2 attempts success, got attempts=%d err=%v",
					resp.Request.Attempt, sendErr)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Every cA send reached the transport exactly once; cB's frame never
	// leaked into cA's stack (which would have retried) and vice versa.
	assertEqual(t, int32(goroutines), aAttempts.Load())
	assertEqual(t, RetrySurfacePin, cA.EffectivePolicy().RetrySurface)
	assertEqual(t, RetrySurfacePin, cB.EffectivePolicy().RetrySurface)
}

func TestPolicyRDerivedRequestsShareClientStack(t *testing.T) {
	tr := &flakyRoundTripper{failUntil: 10}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	scope, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
	assertNil(t, err)
	for i := 0; i < 3; i++ {
		_, sendErr := c.R().Get(fmt.Sprintf("http://policy.example/req-%d", i))
		assertNotNil(t, sendErr)
	}
	scope.Pop()
	assertEqual(t, 3, tr.attempts(), "every R()-derived request must read the same stack")
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Snapshot and request context plumbing
//_______________________________________________________________________

func TestPolicyRequestContextCarriesSendSnapshot(t *testing.T) {
	ts, targetHits := policyRedirectServer(t)
	c := dcnl()
	var seen *policySend
	c.AddRequestMiddleware(func(_ *Client, r *Request) error {
		seen = policySendFromContext(r.Context())
		return nil
	})

	scope, err := c.PushPolicyFrame(PolicyFrame{Redirect: RedirectAdmitRejectRedirect})
	assertNil(t, err)
	resp, sendErr := c.R().Get(ts.URL + "/go")
	scope.Pop()

	assertNil(t, sendErr)
	assertNotNil(t, seen, "send snapshot must ride the request context")
	assertEqual(t, RedirectAdmitRejectRedirect, seen.redirectAdmit())
	assertEqual(t, http.StatusFound, resp.StatusCode())
	assertEqual(t, int32(0), targetHits.Load())
}

func TestPolicySnapshotImmuneToPushAfterEntry(t *testing.T) {
	// Push after Execute entry cannot mutate the in-flight send, and popping
	// after the send leaves a clean stack.
	tr := &flakyRoundTripper{failUntil: 1}
	c := dcnl().SetTransport(tr).SetRetryCount(3).
		SetRetryWaitTime(time.Millisecond).SetRetryMaxWaitTime(2 * time.Millisecond)

	var lateScope *PolicyScope
	var pushed atomic.Bool
	c.AddRequestMiddleware(func(c *Client, _ *Request) error {
		// Retry attempts re-run this chain; push only once.
		if pushed.CompareAndSwap(false, true) {
			// At the before phase retry_surface may still be pushed for future
			// sends, but this send keeps its entry snapshot.
			s, err := c.PushPolicyFrame(PolicyFrame{Retry: RetrySurfaceForceNoRetry})
			if err != nil {
				return err
			}
			lateScope = s
		}
		return nil
	})

	resp, sendErr := c.R().Get("http://policy.example/snapshot-isolation")
	if sendErr != nil {
		t.Fatalf("unexpected err %v", sendErr)
	}
	if lateScope == nil {
		t.Fatalf("expected late scope to be created")
	}
	// This send entered before the push: it keeps retrying per RetryCount.
	assertEqual(t, 2, resp.Request.Attempt)
	lateScope.Pop()
	assertEqual(t, RetrySurfacePin, c.EffectivePolicy().RetrySurface)
}
