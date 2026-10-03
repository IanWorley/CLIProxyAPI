package auth

import (
	"context"
	"sort"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// QuotaRoutingTier orders candidates for the soonest-quota-reset strategy.
// Ranked candidates come first, then fallback candidates, and exhausted
// candidates are never selected.
type QuotaRoutingTier string

const (
	QuotaTierRanked    QuotaRoutingTier = "ranked"
	QuotaTierFallback  QuotaRoutingTier = "fallback"
	QuotaTierExhausted QuotaRoutingTier = "exhausted"
)

// Reason codes explain a quota evaluation. They are stable identifiers for the
// management UI, which localizes them.
const (
	QuotaReasonSoonestReset      = "soonest_reset"
	QuotaReasonUnsupported       = "quota_data_unsupported"
	QuotaReasonMissing           = "quota_data_missing"
	QuotaReasonStale             = "quota_data_stale"
	QuotaReasonNoLongWindowReset = "no_weekly_reset"
	QuotaReasonShortExhausted    = "short_window_exhausted"
	QuotaReasonLongExhausted     = "weekly_window_exhausted"
)

// QuotaRoutingEvaluation is the quota view of one credential for one model.
type QuotaRoutingEvaluation struct {
	Tier   QuotaRoutingTier
	Reason string
	// RankingWindow and RankingResetAt identify the long window used as the ranking key.
	RankingWindow  string
	RankingResetAt time.Time
	// BlockingWindow and BlockedUntil identify the exhausted window that excludes the credential.
	BlockingWindow string
	BlockedUntil   time.Time
	ObservedAt     time.Time
	Stale          bool
	Windows        []QuotaWindow
}

// EvaluateQuotaForRouting classifies a credential for the soonest-quota-reset strategy.
//
// Fallback rules (documented in config.example.yaml):
//   - Shared windows come from the newest of the credential and per-model snapshots.
//     Model-scoped windows (Claude 7d_oi, Codex additional limits) only come from the
//     requested model's own snapshot, because they cannot be attributed otherwise.
//   - A window whose reset time has passed has rolled over and is ignored.
//   - Any applicable exhausted window excludes the credential until it resets, even
//     when the snapshot is stale, so provider limits are never bypassed.
//   - Ranking requires a fresh snapshot with a long (weekly/model-specific) window that
//     reports a future reset. Everything else is a fallback candidate.
func EvaluateQuotaForRouting(auth *Auth, model string, now time.Time) QuotaRoutingEvaluation {
	if auth == nil || !ProviderSupportsQuotaObservation(auth.Provider) {
		return QuotaRoutingEvaluation{Tier: QuotaTierFallback, Reason: QuotaReasonUnsupported}
	}
	windows, observedAt := applicableQuotaWindows(auth, model)
	evaluation := QuotaRoutingEvaluation{
		Tier:       QuotaTierFallback,
		ObservedAt: observedAt,
		Stale:      !observedAt.IsZero() && now.Sub(observedAt) > QuotaObservationMaxAge,
	}
	if len(windows) == 0 {
		evaluation.Reason = QuotaReasonMissing
		return evaluation
	}

	hadWindows := false
	for _, window := range windows {
		if !window.ResetAt.IsZero() && !window.ResetAt.After(now) {
			continue
		}
		hadWindows = true
		evaluation.Windows = append(evaluation.Windows, window)
		windowStale := now.Sub(window.ObservedAt) > QuotaObservationMaxAge
		if window.Exhausted && (!window.ResetAt.IsZero() || !windowStale) {
			if evaluation.Tier != QuotaTierExhausted || window.ResetAt.After(evaluation.BlockedUntil) {
				evaluation.Tier = QuotaTierExhausted
				evaluation.BlockingWindow = window.Name
				evaluation.BlockedUntil = window.ResetAt
				evaluation.Reason = QuotaReasonShortExhausted
				if window.Kind == QuotaWindowLong {
					evaluation.Reason = QuotaReasonLongExhausted
				}
			}
			continue
		}
		if window.Kind != QuotaWindowLong || window.ResetAt.IsZero() || windowStale {
			continue
		}
		if evaluation.RankingResetAt.IsZero() || window.ResetAt.Before(evaluation.RankingResetAt) {
			evaluation.RankingResetAt = window.ResetAt
			evaluation.RankingWindow = window.Name
		}
	}

	switch {
	case evaluation.Tier == QuotaTierExhausted:
	case !hadWindows || evaluation.Stale:
		evaluation.Reason = QuotaReasonStale
	case evaluation.RankingResetAt.IsZero():
		evaluation.Reason = QuotaReasonNoLongWindowReset
	default:
		evaluation.Tier = QuotaTierRanked
		evaluation.Reason = QuotaReasonSoonestReset
	}
	if evaluation.Tier != QuotaTierRanked {
		evaluation.RankingResetAt = time.Time{}
		evaluation.RankingWindow = ""
	}
	return evaluation
}

// applicableQuotaWindows merges the credential and per-model snapshots and returns
// the observation time of the snapshot that supplied the shared windows.
func applicableQuotaWindows(auth *Auth, model string) ([]QuotaWindow, time.Time) {
	shared := auth.Quota
	var modelQuota *QuotaState
	if modelKey := canonicalModelKey(model); modelKey != "" {
		for stateModel, state := range auth.ModelStates {
			if state != nil && !state.Quota.ObservedAt.IsZero() && canonicalModelKey(stateModel) == modelKey {
				modelQuota = &state.Quota
				break
			}
		}
	}
	if modelQuota != nil && !modelQuota.ObservedAt.Before(shared.ObservedAt) {
		shared = *modelQuota
	}

	var windows []QuotaWindow
	for _, window := range parseQuotaWindows(auth.Provider, shared) {
		if !window.ModelScoped {
			windows = append(windows, window)
		}
	}
	if modelQuota != nil {
		for _, window := range parseQuotaWindows(auth.Provider, *modelQuota) {
			if window.ModelScoped {
				windows = append(windows, window)
			}
		}
	}
	return windows, shared.ObservedAt
}

// rankedQuotaCandidate pairs a credential with its evaluation.
type rankedQuotaCandidate struct {
	auth       *Auth
	evaluation QuotaRoutingEvaluation
}

var quotaTierOrder = map[QuotaRoutingTier]int{
	QuotaTierRanked:    0,
	QuotaTierFallback:  1,
	QuotaTierExhausted: 2,
}

// rankByQuotaReset orders candidates deterministically:
//  1. ranked: earliest long-window reset first, then credential ID
//  2. fallback: credential ID (the fill-first order)
//  3. exhausted: earliest recovery first, then credential ID (never selected)
func rankByQuotaReset(auths []*Auth, model string, now time.Time) []rankedQuotaCandidate {
	ranked := make([]rankedQuotaCandidate, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		ranked = append(ranked, rankedQuotaCandidate{auth: auth, evaluation: EvaluateQuotaForRouting(auth, model, now)})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		left, right := ranked[i].evaluation, ranked[j].evaluation
		if left.Tier != right.Tier {
			return quotaTierOrder[left.Tier] < quotaTierOrder[right.Tier]
		}
		switch left.Tier {
		case QuotaTierRanked:
			if !left.RankingResetAt.Equal(right.RankingResetAt) {
				return left.RankingResetAt.Before(right.RankingResetAt)
			}
		case QuotaTierExhausted:
			if !left.BlockedUntil.Equal(right.BlockedUntil) {
				return left.BlockedUntil.Before(right.BlockedUntil)
			}
		}
		return ranked[i].auth.ID < ranked[j].auth.ID
	})
	return ranked
}

// SoonestQuotaResetSelector spends allowance that resets soonest first.
//
// It only ranks credentials that the manager already found usable (provider and model
// support, not disabled, valid credentials, no cooldown). Session stickiness and
// failover come from the SessionAffinitySelector that always wraps this selector.
type SoonestQuotaResetSelector struct {
	decisions *RoutingDecisionLog
	nowFunc   func() time.Time
}

// NewSoonestQuotaResetSelector creates the selector with an empty decision log.
func NewSoonestQuotaResetSelector() *SoonestQuotaResetSelector {
	return &SoonestQuotaResetSelector{decisions: NewRoutingDecisionLog()}
}

// Decisions returns recent selection decisions, newest first.
func (s *SoonestQuotaResetSelector) Decisions() []RoutingDecision {
	if s == nil {
		return nil
	}
	return s.decisions.Snapshot()
}

func (s *SoonestQuotaResetSelector) now() time.Time {
	if s != nil && s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now()
}

// Pick selects the usable credential whose weekly/model-specific quota resets soonest.
func (s *SoonestQuotaResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := s.now()
	available, errAvailable := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	ranked := rankByQuotaReset(available, model, now)
	if len(ranked) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	best := ranked[0]
	if best.evaluation.Tier == QuotaTierExhausted {
		s.decisions.Record(newRoutingDecision(ctx, provider, model, nil, ranked, now))
		// Every candidate is exhausted: report the earliest provider reset instead of
		// cycling through credentials the provider would reject.
		if best.evaluation.BlockedUntil.After(now) {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			return nil, newModelCooldownError(model, providerForError, best.evaluation.BlockedUntil.Sub(now))
		}
		return nil, newAuthUnavailableError(time.Time{}, now)
	}
	s.decisions.Record(newRoutingDecision(ctx, provider, model, best.auth, ranked, now))
	return best.auth, nil
}

// Routing decision kinds describe why the selector was asked to choose.
const (
	RoutingDecisionNewSession = "new_session"
	RoutingDecisionFailover   = "failover"
	RoutingDecisionNoSession  = "no_session"
)

type routingPickIntentKey struct{}

type routingPickIntent struct {
	kind           string
	previousAuthID string
}

// withRoutingPickIntent records why the session affinity wrapper delegated selection.
func withRoutingPickIntent(ctx context.Context, kind, previousAuthID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, routingPickIntentKey{}, routingPickIntent{kind: kind, previousAuthID: previousAuthID})
}

func routingPickIntentFromContext(ctx context.Context) routingPickIntent {
	if ctx != nil {
		if intent, ok := ctx.Value(routingPickIntentKey{}).(routingPickIntent); ok {
			return intent
		}
	}
	return routingPickIntent{kind: RoutingDecisionNoSession}
}

const (
	maxRoutingDecisions          = 50
	maxRoutingDecisionCandidates = 20
)

// RoutingDecisionCandidate explains how one credential ranked in a decision.
// It stores credential IDs internally; management responses map them to auth indexes.
type RoutingDecisionCandidate struct {
	AuthID         string
	Tier           QuotaRoutingTier
	Reason         string
	RankingWindow  string
	RankingResetAt time.Time
	BlockingWindow string
	BlockedUntil   time.Time
}

// RoutingDecision records one selection made by the soonest-quota-reset strategy.
type RoutingDecision struct {
	At             time.Time
	Kind           string
	Provider       string
	Model          string
	SelectedAuthID string
	PreviousAuthID string
	Candidates     []RoutingDecisionCandidate
	// Repeat counts consecutive identical decisions collapsed into this entry.
	Repeat int
}

func newRoutingDecision(ctx context.Context, provider, model string, selected *Auth, ranked []rankedQuotaCandidate, now time.Time) RoutingDecision {
	intent := routingPickIntentFromContext(ctx)
	decision := RoutingDecision{
		At:             now,
		Kind:           intent.kind,
		Provider:       provider,
		Model:          canonicalModelKey(model),
		PreviousAuthID: intent.previousAuthID,
		Repeat:         1,
	}
	if selected != nil {
		decision.SelectedAuthID = selected.ID
	}
	limit := len(ranked)
	if limit > maxRoutingDecisionCandidates {
		limit = maxRoutingDecisionCandidates
	}
	decision.Candidates = make([]RoutingDecisionCandidate, 0, limit)
	for _, candidate := range ranked[:limit] {
		decision.Candidates = append(decision.Candidates, RoutingDecisionCandidate{
			AuthID:         candidate.auth.ID,
			Tier:           candidate.evaluation.Tier,
			Reason:         candidate.evaluation.Reason,
			RankingWindow:  candidate.evaluation.RankingWindow,
			RankingResetAt: candidate.evaluation.RankingResetAt,
			BlockingWindow: candidate.evaluation.BlockingWindow,
			BlockedUntil:   candidate.evaluation.BlockedUntil,
		})
	}
	return decision
}

// RoutingDecisionLog is a bounded, concurrency-safe ring of recent decisions.
type RoutingDecisionLog struct {
	mu        sync.Mutex
	decisions []RoutingDecision
}

// NewRoutingDecisionLog creates an empty decision log.
func NewRoutingDecisionLog() *RoutingDecisionLog {
	return &RoutingDecisionLog{}
}

// Record appends a decision, collapsing it into the newest entry when the outcome
// repeats (for example, requests without a session that keep choosing the same credential).
func (l *RoutingDecisionLog) Record(decision RoutingDecision) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if last := len(l.decisions) - 1; last >= 0 && sameRoutingOutcome(l.decisions[last], decision) {
		decision.Repeat = l.decisions[last].Repeat + 1
		l.decisions[last] = decision
		return
	}
	if len(l.decisions) >= maxRoutingDecisions {
		l.decisions = append(l.decisions[:0], l.decisions[1:]...)
	}
	l.decisions = append(l.decisions, decision)
}

// Snapshot returns a copy of the log, newest first.
func (l *RoutingDecisionLog) Snapshot() []RoutingDecision {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]RoutingDecision, len(l.decisions))
	for i := range l.decisions {
		out[len(l.decisions)-1-i] = l.decisions[i]
	}
	return out
}

func sameRoutingOutcome(a, b RoutingDecision) bool {
	if a.Kind != b.Kind || a.Provider != b.Provider || a.Model != b.Model ||
		a.SelectedAuthID != b.SelectedAuthID || a.PreviousAuthID != b.PreviousAuthID ||
		len(a.Candidates) != len(b.Candidates) {
		return false
	}
	for i := range a.Candidates {
		if a.Candidates[i].AuthID != b.Candidates[i].AuthID || a.Candidates[i].Reason != b.Candidates[i].Reason {
			return false
		}
	}
	return true
}

// soonestQuotaResetSelectorOf unwraps the configured selector.
func soonestQuotaResetSelectorOf(selector Selector) *SoonestQuotaResetSelector {
	switch typed := selector.(type) {
	case *SoonestQuotaResetSelector:
		return typed
	case *SessionAffinitySelector:
		if typed != nil {
			return soonestQuotaResetSelectorOf(typed.fallback)
		}
	}
	return nil
}
