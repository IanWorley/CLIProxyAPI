package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

const (
	quotaRoutingShortReset = 2 * time.Hour
	quotaRoutingSoonReset  = 24 * time.Hour
	quotaRoutingLateReset  = 96 * time.Hour
)

func freshClaudeRoutingAuth(id string, now time.Time, weeklyReset time.Duration, shortStatus string) *Auth {
	auth := claudeQuotaAuth(id, now.Add(weeklyReset), shortStatus)
	auth.Quota.ObservedAt = now
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Reset"] = unixSignal(now.Add(quotaRoutingShortReset))
	return auth
}

func registerQuotaRoutingAuth(t *testing.T, manager *Manager, auth *Auth, models ...string) {
	t.Helper()
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register(%s): %v", auth.ID, errRegister)
	}
	infos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		infos = append(infos, &registry.ModelInfo{ID: model})
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, infos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
}

func TestManagerSoonestQuotaResetFailsOverAfterPassiveExhaustion(t *testing.T) {
	const model = "passive-quota-model"
	now := time.Now()
	selector := NewSoonestQuotaResetSelector()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, TTL: time.Hour})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	registerQuotaRoutingAuth(t, manager, freshClaudeRoutingAuth("passive-soon", now, quotaRoutingSoonReset, "allowed"), model)
	registerQuotaRoutingAuth(t, manager, freshClaudeRoutingAuth("passive-late", now, quotaRoutingLateReset, "allowed"), model)

	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"passive-session"}}}
	first, _, errPick := manager.pickNext(context.Background(), "claude", model, opts, nil)
	if errPick != nil || first == nil || first.ID != "passive-soon" {
		t.Fatalf("first pick ID = %q, error = %v; want passive-soon", quotaRoutingAuthID(first), errPick)
	}

	ctx := internallogging.WithResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, http.Header{
		"Anthropic-Ratelimit-Unified-5h-Status":      []string{"rejected"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": []string{"1.0"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       []string{unixSignal(now.Add(quotaRoutingShortReset))},
		"Anthropic-Ratelimit-Unified-7d-Status":      []string{"allowed"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": []string{"0.3"},
		"Anthropic-Ratelimit-Unified-7d-Reset":       []string{unixSignal(now.Add(quotaRoutingSoonReset))},
	})
	manager.MarkResult(ctx, Result{AuthID: first.ID, Provider: "claude", Model: model, Success: true})

	selected, _, errPick := manager.pickNext(context.Background(), "claude", model, opts, nil)
	if errPick != nil || selected == nil || selected.ID != "passive-late" {
		t.Fatalf("pick after passive exhaustion ID = %q, error = %v; want passive-late", quotaRoutingAuthID(selected), errPick)
	}
	decisions := selector.Decisions()
	if len(decisions) == 0 || decisions[0].Kind != RoutingDecisionFailover || decisions[0].PreviousAuthID != first.ID {
		t.Fatalf("failover decision = %+v; want previous credential %s", decisions, first.ID)
	}
	foundExhausted := false
	for _, candidate := range decisions[0].Candidates {
		if candidate.AuthID == first.ID && candidate.Tier == QuotaTierExhausted {
			foundExhausted = true
		}
	}
	if !foundExhausted {
		t.Fatalf("failover candidates = %+v; want exhausted credential %s", decisions[0].Candidates, first.ID)
	}
}

func TestManagerSoonestQuotaResetUsesLowerPriorityWhenTopIsExhausted(t *testing.T) {
	const model = "priority-quota-model"
	now := time.Now()
	selector := NewSoonestQuotaResetSelector()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, TTL: time.Hour})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	high := freshClaudeRoutingAuth("priority-exhausted", now, quotaRoutingSoonReset, "rejected")
	high.Attributes = map[string]string{"priority": "10"}
	low := freshClaudeRoutingAuth("priority-usable", now, quotaRoutingLateReset, "allowed")
	low.Attributes = map[string]string{"priority": "0"}
	registerQuotaRoutingAuth(t, manager, high, model)
	registerQuotaRoutingAuth(t, manager, low, model)

	selected, _, errPick := manager.pickNext(context.Background(), "claude", model, cliproxyexecutor.Options{}, nil)
	if errPick != nil || selected == nil || selected.ID != low.ID {
		t.Fatalf("pick with exhausted top priority ID = %q, error = %v; want %s", quotaRoutingAuthID(selected), errPick, low.ID)
	}
}

func TestManagerSoonestQuotaResetAppliesAliasedModelQuota(t *testing.T) {
	const (
		routeModel    = "friendly-quota-model"
		upstreamModel = "claude-fable-5-1"
	)
	now := time.Now()
	selector := NewSoonestQuotaResetSelector()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, TTL: time.Hour})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	manager.SetOAuthModelAlias(map[string][]internalconfig.OAuthModelAlias{
		"claude": {{Name: upstreamModel, Alias: routeModel}},
	})
	soon := freshClaudeRoutingAuth("alias-exhausted", now, quotaRoutingSoonReset, "allowed")
	soon.ModelStates = map[string]*ModelState{upstreamModel: {Quota: soon.Quota.Clone()}}
	soon.ModelStates[upstreamModel].Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Status"] = "rejected"
	soon.ModelStates[upstreamModel].Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = unixSignal(now.Add(quotaRoutingLateReset))
	later := freshClaudeRoutingAuth("alias-usable", now, quotaRoutingLateReset, "allowed")
	registerQuotaRoutingAuth(t, manager, soon, routeModel, upstreamModel)
	registerQuotaRoutingAuth(t, manager, later, routeModel, upstreamModel)

	selected, _, errPick := manager.pickNext(context.Background(), "claude", routeModel, cliproxyexecutor.Options{}, nil)
	if errPick != nil || selected == nil || selected.ID != later.ID {
		t.Fatalf("aliased model pick ID = %q, error = %v; want %s", quotaRoutingAuthID(selected), errPick, later.ID)
	}
	report := manager.QuotaRoutingReport("claude", routeModel)
	found := false
	for _, account := range report.Accounts {
		if account.AuthIndex == safeAuthIndex(soon) {
			found = true
			if account.Eligible || account.Reason != QuotaReasonLongExhausted {
				t.Fatalf("aliased model status = %+v; want weekly exhaustion", account)
			}
		}
	}
	if !found {
		t.Fatal("aliased model status omitted the exhausted credential")
	}
}

func quotaRoutingAuthID(auth *Auth) string {
	if auth == nil {
		return ""
	}
	return auth.ID
}

func TestSoonestQuotaResetKnownRecoveryWinsOverMissingReset(t *testing.T) {
	now := quotaTestNow
	unknown := freshClaudeRoutingAuth("a-unknown-reset", now, quotaRoutingSoonReset, "rejected")
	delete(unknown.Quota.Signals, "Anthropic-Ratelimit-Unified-5h-Reset")
	known := freshClaudeRoutingAuth("b-known-reset", now, quotaRoutingSoonReset, "rejected")
	selector := newTestSoonestSelector()

	_, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{unknown, known})
	var cooldownErr *modelCooldownError
	if !errors.As(errPick, &cooldownErr) {
		t.Fatalf("Pick error = %v; want model cooldown", errPick)
	}
	if got, want := cooldownErr.Headers().Get("Retry-After"), strconv.Itoa(int(quotaRoutingShortReset.Seconds())); got != want {
		t.Fatalf("Retry-After = %q; want %q", got, want)
	}
}

func TestSoonestQuotaResetUsesHTTPWhenWebsocketCredentialIsExhausted(t *testing.T) {
	now := quotaTestNow
	quotaSignals := func(used string) QuotaState {
		return QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":          used,
			"X-Codex-Primary-Reset-After-Seconds":   strconv.Itoa(int(quotaRoutingShortReset.Seconds())),
			"X-Codex-Secondary-Used-Percent":        "20",
			"X-Codex-Secondary-Reset-After-Seconds": strconv.Itoa(int(quotaRoutingSoonReset.Seconds())),
		}}
	}
	websocket := &Auth{ID: "websocket-exhausted", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"websockets": "true"}, Quota: quotaSignals("100")}
	httpOnly := &Auth{ID: "http-usable", Provider: "codex", Status: StatusActive, Quota: quotaSignals("20")}
	selector := newTestSoonestSelector()
	ctx := cliproxyexecutor.WithDownstreamWebsocket(context.Background())

	selected, errPick := selector.Pick(ctx, "codex", "", cliproxyexecutor.Options{}, []*Auth{websocket, httpOnly})
	if errPick != nil || selected == nil || selected.ID != httpOnly.ID {
		t.Fatalf("websocket request selected ID = %q, error = %v; want %s", quotaRoutingAuthID(selected), errPick, httpOnly.ID)
	}
}

// codexSparkLimitAuth has a healthy base limit and an exhausted Spark additional limit,
// observed on a response for the given model.
func codexSparkLimitAuth(model, activeLimit string) *Auth {
	signals := map[string]string{
		"X-Codex-Secondary-Used-Percent":                        "40",
		"X-Codex-Secondary-Reset-At":                            unixSignal(quotaTestNow.Add(quotaRoutingSoonReset)),
		"X-Codex-Bengalfox-Limit-Name":                          "GPT-5.3-Codex-Spark",
		"X-Codex-Bengalfox-Secondary-Used-Percent":              "100",
		"X-Codex-Bengalfox-Secondary-Reset-At":                  unixSignal(quotaTestNow.Add(quotaRoutingLateReset)),
		"X-Codex-Additional-Other-Limit-Secondary-Used-Percent": "100",
	}
	if activeLimit != "" {
		signals["X-Codex-Active-Limit"] = activeLimit
	}
	quota := QuotaState{ObservedAt: quotaTestNow, Signals: signals}
	return &Auth{ID: "codex-spark", Provider: "codex", Quota: quota, ModelStates: map[string]*ModelState{model: {Quota: quota}}}
}

func TestEvaluateQuotaForRoutingScopesCodexAdditionalLimitsToTheirModel(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		model       string
		activeLimit string
		wantTier    QuotaRoutingTier
	}{
		{name: "other model ignores spark limit", model: "gpt-5.5", activeLimit: "codex", wantTier: QuotaTierRanked},
		{name: "limit named for the model applies", model: "gpt-5.3-codex-spark", wantTier: QuotaTierExhausted},
		{name: "active limit applies", model: "gpt-5.5", activeLimit: "codex_bengalfox", wantTier: QuotaTierExhausted},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := EvaluateQuotaForRouting(codexSparkLimitAuth(testCase.model, testCase.activeLimit), testCase.model, quotaTestNow)
			if got.Tier != testCase.wantTier {
				t.Fatalf("tier = %s (blocking %q), want %s", got.Tier, got.BlockingWindow, testCase.wantTier)
			}
		})
	}
}

func TestEvaluateQuotaForRoutingHonorsCodexLimitReached(t *testing.T) {
	auth := &Auth{ID: "codex-reached", Provider: "codex", Quota: QuotaState{
		ObservedAt: quotaTestNow,
		Signals: map[string]string{
			"X-Codex-Limit-Reached":          "true",
			"X-Codex-Primary-Used-Percent":   "99",
			"X-Codex-Primary-Reset-At":       unixSignal(quotaTestNow.Add(quotaRoutingShortReset)),
			"X-Codex-Secondary-Used-Percent": "40",
			"X-Codex-Secondary-Reset-At":     unixSignal(quotaTestNow.Add(quotaRoutingSoonReset)),
		},
	}}
	got := EvaluateQuotaForRouting(auth, "", quotaTestNow)
	if got.Tier != QuotaTierExhausted || got.BlockingWindow != "primary" {
		t.Fatalf("evaluation = (%s, %q), want exhausted by primary", got.Tier, got.BlockingWindow)
	}
}

func TestSessionAffinityLCPRecordsQuotaFailover(t *testing.T) {
	quotaSelector := newTestSoonestSelector()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: quotaSelector, TTL: time.Hour})
	defer affinity.Stop()

	sooner := freshClaudeRoutingAuth("lcp-sooner", quotaTestNow, quotaRoutingSoonReset, "allowed")
	later := freshClaudeRoutingAuth("lcp-later", quotaTestNow, quotaRoutingLateReset, "allowed")
	pick := func() *Auth {
		t.Helper()
		opts := cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FormatOpenAI,
			OriginalRequest: []byte(`{"messages":[{"role":"user","content":"lcp quota failover"}]}`),
			Metadata:        map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "caller-a"},
		}
		auth, errPick := affinity.Pick(context.Background(), "claude", "lcp-model", opts, []*Auth{sooner, later})
		if errPick != nil {
			t.Fatalf("Pick: %v", errPick)
		}
		return auth
	}

	if got := pick(); got.ID != sooner.ID {
		t.Fatalf("new session = %s, want %s", got.ID, sooner.ID)
	}
	sooner.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Status"] = "rejected"
	if got := pick(); got.ID != later.ID {
		t.Fatalf("failover = %s, want %s", got.ID, later.ID)
	}
	decision := quotaSelector.Decisions()[0]
	if decision.Kind != RoutingDecisionFailover || decision.PreviousAuthID != sooner.ID {
		t.Fatalf("decision = (%s, %q), want failover from %s", decision.Kind, decision.PreviousAuthID, sooner.ID)
	}
}

func TestManagerQuotaRoutingReportInactiveUnderHomeDispatch(t *testing.T) {
	manager := NewManager(nil, NewSoonestQuotaResetSelector(), nil)
	manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	if manager.QuotaRoutingReport("", "").Active {
		t.Fatal("report.Active = true while Home owns selection, want false")
	}
}
