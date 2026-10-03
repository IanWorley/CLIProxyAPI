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
