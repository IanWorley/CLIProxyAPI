package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var quotaTestNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func unixSignal(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// claudeQuotaAuth builds a Claude credential with a fresh passive snapshot.
func claudeQuotaAuth(id string, weeklyReset time.Time, shortStatus string) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Status:   StatusActive,
		Quota: QuotaState{
			ObservedAt: quotaTestNow.Add(-time.Minute),
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-5h-Status":      shortStatus,
				"Anthropic-Ratelimit-Unified-5h-Utilization": "0.40",
				"Anthropic-Ratelimit-Unified-5h-Reset":       unixSignal(quotaTestNow.Add(2 * time.Hour)),
				"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
				"Anthropic-Ratelimit-Unified-7d-Utilization": "0.30",
				"Anthropic-Ratelimit-Unified-7d-Reset":       unixSignal(weeklyReset),
			},
		},
	}
}

func newTestSoonestSelector() *SoonestQuotaResetSelector {
	selector := NewSoonestQuotaResetSelector()
	selector.nowFunc = func() time.Time { return quotaTestNow }
	return selector
}

func TestEvaluateQuotaForRouting(t *testing.T) {
	tomorrow := quotaTestNow.Add(24 * time.Hour)
	for _, testCase := range []struct {
		name       string
		auth       *Auth
		model      string
		wantTier   QuotaRoutingTier
		wantReason string
	}{
		{
			name:       "fresh weekly reset is ranked",
			auth:       claudeQuotaAuth("a", tomorrow, "allowed"),
			wantTier:   QuotaTierRanked,
			wantReason: QuotaReasonSoonestReset,
		},
		{
			name:       "exhausted short window excludes despite weekly allowance",
			auth:       claudeQuotaAuth("a", tomorrow, "rejected"),
			wantTier:   QuotaTierExhausted,
			wantReason: QuotaReasonShortExhausted,
		},
		{
			name:       "provider without quota telemetry falls back",
			auth:       &Auth{ID: "a", Provider: "gemini"},
			wantTier:   QuotaTierFallback,
			wantReason: QuotaReasonUnsupported,
		},
		{
			name:       "missing snapshot falls back",
			auth:       &Auth{ID: "a", Provider: "claude"},
			wantTier:   QuotaTierFallback,
			wantReason: QuotaReasonMissing,
		},
		{
			name: "stale snapshot falls back",
			auth: func() *Auth {
				auth := claudeQuotaAuth("a", tomorrow, "allowed")
				auth.Quota.ObservedAt = quotaTestNow.Add(-QuotaObservationMaxAge - time.Minute)
				return auth
			}(),
			wantTier:   QuotaTierFallback,
			wantReason: QuotaReasonStale,
		},
		{
			name: "stale exhaustion with a future reset still excludes",
			auth: func() *Auth {
				auth := claudeQuotaAuth("a", tomorrow, "rejected")
				auth.Quota.ObservedAt = quotaTestNow.Add(-QuotaObservationMaxAge - time.Minute)
				return auth
			}(),
			wantTier:   QuotaTierExhausted,
			wantReason: QuotaReasonShortExhausted,
		},
		{
			name:       "weekly window that already reset falls back",
			auth:       claudeQuotaAuth("a", quotaTestNow.Add(-time.Minute), "allowed"),
			wantTier:   QuotaTierFallback,
			wantReason: QuotaReasonNoLongWindowReset,
		},
		{
			name: "codex weekly reset derived from reset-after-seconds",
			auth: &Auth{ID: "a", Provider: "codex", Quota: QuotaState{
				ObservedAt: quotaTestNow.Add(-time.Minute),
				Signals: map[string]string{
					"X-Codex-Primary-Used-Percent":          "20",
					"X-Codex-Primary-Window-Minutes":        "300",
					"X-Codex-Primary-Reset-After-Seconds":   "3600",
					"X-Codex-Secondary-Used-Percent":        "50",
					"X-Codex-Secondary-Window-Minutes":      "10080",
					"X-Codex-Secondary-Reset-After-Seconds": "86400",
				},
			}},
			wantTier:   QuotaTierRanked,
			wantReason: QuotaReasonSoonestReset,
		},
		{
			name: "devin exhausted weekly allowance excludes",
			auth: &Auth{ID: "a", Provider: "devin", Quota: QuotaState{
				ObservedAt: quotaTestNow.Add(-time.Minute),
				Signals: map[string]string{
					"daily_quota_remaining_percent":  "80%",
					"weekly_quota_remaining_percent": "0%",
					"weekly_quota_reset_at":          tomorrow.Format(time.RFC3339),
				},
			}},
			wantTier:   QuotaTierExhausted,
			wantReason: QuotaReasonLongExhausted,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := EvaluateQuotaForRouting(testCase.auth, testCase.model, quotaTestNow)
			if got.Tier != testCase.wantTier || got.Reason != testCase.wantReason {
				t.Fatalf("evaluation = (%s, %s), want (%s, %s)", got.Tier, got.Reason, testCase.wantTier, testCase.wantReason)
			}
		})
	}
}

func TestEvaluateQuotaForRoutingCodexWeeklyResetTime(t *testing.T) {
	auth := &Auth{ID: "a", Provider: "codex", Quota: QuotaState{
		ObservedAt: quotaTestNow,
		Signals: map[string]string{
			"X-Codex-Secondary-Used-Percent":        "50",
			"X-Codex-Secondary-Reset-After-Seconds": "86400",
		},
	}}
	got := EvaluateQuotaForRouting(auth, "", quotaTestNow)
	if want := quotaTestNow.Add(24 * time.Hour); !got.RankingResetAt.Equal(want) || got.RankingWindow != "secondary" {
		t.Fatalf("ranking = (%s, %s), want (secondary, %s)", got.RankingWindow, got.RankingResetAt, want)
	}
}

func TestEvaluateQuotaForRoutingModelScopedWindowNeedsModelSnapshot(t *testing.T) {
	model := "claude-fable-5-1"
	auth := claudeQuotaAuth("a", quotaTestNow.Add(48*time.Hour), "allowed")
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Status"] = "rejected"
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = unixSignal(quotaTestNow.Add(72 * time.Hour))

	// The credential-level snapshot cannot attribute 7d_oi to the requested model.
	if got := EvaluateQuotaForRouting(auth, model, quotaTestNow); got.Tier != QuotaTierRanked {
		t.Fatalf("without model snapshot tier = %s, want ranked", got.Tier)
	}

	auth.ModelStates = map[string]*ModelState{model: {Quota: auth.Quota.Clone()}}
	got := EvaluateQuotaForRouting(auth, model, quotaTestNow)
	if got.Tier != QuotaTierExhausted || got.BlockingWindow != "7d_oi" {
		t.Fatalf("with model snapshot = (%s, %s), want exhausted by 7d_oi", got.Tier, got.BlockingWindow)
	}
}

func TestSoonestQuotaResetSelectorPrefersEarliestWeeklyReset(t *testing.T) {
	selector := newTestSoonestSelector()
	auths := []*Auth{
		{ID: "a-no-data", Provider: "claude", Status: StatusActive},
		claudeQuotaAuth("b-four-days", quotaTestNow.Add(96*time.Hour), "allowed"),
		claudeQuotaAuth("c-tomorrow", quotaTestNow.Add(24*time.Hour), "allowed"),
	}
	got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if errPick != nil {
		t.Fatalf("Pick: %v", errPick)
	}
	if got.ID != "c-tomorrow" {
		t.Fatalf("Pick = %s, want c-tomorrow", got.ID)
	}

	decisions := selector.Decisions()
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}
	var order []string
	for _, candidate := range decisions[0].Candidates {
		order = append(order, candidate.AuthID+":"+candidate.Reason)
	}
	want := []string{"c-tomorrow:soonest_reset", "b-four-days:soonest_reset", "a-no-data:quota_data_missing"}
	for i := range want {
		if i >= len(order) || order[i] != want[i] {
			t.Fatalf("candidate order = %v, want %v", order, want)
		}
	}
}

func TestSoonestQuotaResetSelectorSkipsShortWindowExhaustion(t *testing.T) {
	selector := newTestSoonestSelector()
	auths := []*Auth{
		claudeQuotaAuth("a-tomorrow-5h-exhausted", quotaTestNow.Add(24*time.Hour), "rejected"),
		claudeQuotaAuth("b-four-days", quotaTestNow.Add(96*time.Hour), "allowed"),
	}
	got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if errPick != nil {
		t.Fatalf("Pick: %v", errPick)
	}
	if got.ID != "b-four-days" {
		t.Fatalf("Pick = %s, want b-four-days", got.ID)
	}
}

func TestSoonestQuotaResetSelectorMissingDataUsesCredentialIDOrder(t *testing.T) {
	selector := newTestSoonestSelector()
	auths := []*Auth{
		{ID: "b", Provider: "claude", Status: StatusActive},
		{ID: "a", Provider: "claude", Status: StatusActive},
	}
	for range 3 {
		got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick: %v", errPick)
		}
		if got.ID != "a" {
			t.Fatalf("Pick = %s, want deterministic fallback a", got.ID)
		}
	}
}

func TestSoonestQuotaResetSelectorAllExhaustedReturnsRetryAfter(t *testing.T) {
	selector := newTestSoonestSelector()
	auths := []*Auth{
		claudeQuotaAuth("a", quotaTestNow.Add(24*time.Hour), "rejected"),
		claudeQuotaAuth("b", quotaTestNow.Add(96*time.Hour), "rejected"),
	}
	_, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	var cooldownErr *modelCooldownError
	if !errors.As(errPick, &cooldownErr) {
		t.Fatalf("Pick error = %v, want model cooldown", errPick)
	}
	if cooldownErr.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", cooldownErr.StatusCode())
	}
	// Both short windows reset in 2h; that is the earliest time a request can succeed.
	if got := cooldownErr.Headers().Get("Retry-After"); got != strconv.Itoa(int((2 * time.Hour).Seconds())) {
		t.Fatalf("Retry-After = %s, want 7200", got)
	}
}

func TestManagerSoonestQuotaResetKeepsSessionAndFailsOver(t *testing.T) {
	ctx := context.Background()
	provider := "claude"
	model := "soonest-reset-model"
	soonID := "soonest-reset-tomorrow"
	laterID := "soonest-reset-four-days"

	selector := newTestSoonestSelector()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, TTL: time.Hour})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

	for _, auth := range []*Auth{
		claudeQuotaAuth(soonID, quotaTestNow.Add(24*time.Hour), "allowed"),
		claudeQuotaAuth(laterID, quotaTestNow.Add(96*time.Hour), "allowed"),
	} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
	}

	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"conversation-1"}}}
	pick := func() *Auth {
		t.Helper()
		auth, _, errPick := manager.pickNext(ctx, provider, model, opts, nil)
		if errPick != nil {
			t.Fatalf("pickNext: %v", errPick)
		}
		return auth
	}

	if got := pick(); got.ID != soonID {
		t.Fatalf("new session = %s, want %s", got.ID, soonID)
	}

	// Another credential now ranks higher; the active session must not move.
	sooner := claudeQuotaAuth(laterID, quotaTestNow.Add(time.Hour), "allowed")
	if _, errUpdate := manager.Update(WithSkipPersist(ctx), sooner); errUpdate != nil {
		t.Fatalf("Update: %v", errUpdate)
	}
	if got := pick(); got.ID != soonID {
		t.Fatalf("bound session moved to %s, want %s", got.ID, soonID)
	}

	// The bound credential is rate limited: the session fails over and keeps the new binding.
	retryAfter := 30 * time.Minute
	manager.MarkResult(ctx, Result{
		AuthID:     soonID,
		Provider:   provider,
		Model:      model,
		RetryAfter: &retryAfter,
		Error:      &Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limited"},
	})
	if got := pick(); got.ID != laterID {
		t.Fatalf("failover = %s, want %s", got.ID, laterID)
	}
	decisions := selector.Decisions()
	if len(decisions) == 0 || decisions[0].Kind != RoutingDecisionFailover || decisions[0].PreviousAuthID != soonID {
		t.Fatalf("latest decision = %+v, want failover from %s", decisions, soonID)
	}

	manager.MarkResult(ctx, Result{AuthID: soonID, Provider: provider, Model: model, Success: true})
	if got := pick(); got.ID != laterID {
		t.Fatalf("after recovery session = %s, want retained binding %s", got.ID, laterID)
	}
}

func TestManagerQuotaRoutingReportExplainsEligibilityWithSafeIdentifiers(t *testing.T) {
	ctx := context.Background()
	selector := NewSoonestQuotaResetSelector()
	manager := NewManager(nil, selector, nil)
	now := time.Now()

	sooner := claudeQuotaAuth("report-claude-sooner@example.invalid", now.Add(24*time.Hour), "allowed")
	sooner.Quota.ObservedAt = now
	later := claudeQuotaAuth("report-claude-later@example.invalid", now.Add(96*time.Hour), "allowed")
	later.Quota.ObservedAt = now
	disabled := &Auth{ID: "report-codex-disabled@example.invalid", Provider: "codex", Status: StatusDisabled, Disabled: true}
	for _, auth := range []*Auth{sooner, later, disabled} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}

	report := manager.QuotaRoutingReport("", "")
	if !report.Active {
		t.Fatal("report.Active = false, want true")
	}
	byIndex := map[string]QuotaRoutingAccountStatus{}
	for _, account := range report.Accounts {
		if strings.Contains(account.AuthIndex, "@") {
			t.Fatalf("auth index %q leaks the credential ID", account.AuthIndex)
		}
		byIndex[account.AuthIndex] = account
	}
	soonerStatus := byIndex[safeAuthIndex(sooner)]
	laterStatus := byIndex[safeAuthIndex(later)]
	disabledStatus := byIndex[safeAuthIndex(disabled)]
	if soonerStatus.Rank != 1 || laterStatus.Rank != 2 {
		t.Fatalf("claude ranks = (%d, %d), want (1, 2)", soonerStatus.Rank, laterStatus.Rank)
	}
	if disabledStatus.Eligible || disabledStatus.Reason != RoutingExclusionDisabled || disabledStatus.Rank != 0 {
		t.Fatalf("disabled status = %+v, want ineligible with reason disabled", disabledStatus)
	}
}
