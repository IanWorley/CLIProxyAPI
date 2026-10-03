package auth

import (
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// Exclusion reasons reported before quota is considered. They mirror the checks the
// manager applies before the selector ever sees a credential.
const (
	RoutingExclusionDisabled           = "disabled"
	RoutingExclusionInvalidCredentials = "invalid_credentials"
	RoutingExclusionModelUnsupported   = "model_unsupported"
	RoutingExclusionCooldown           = "cooldown"
)

// QuotaRoutingWindowStatus is a management view of one quota window.
type QuotaRoutingWindowStatus struct {
	Name             string          `json:"name"`
	Kind             QuotaWindowKind `json:"kind"`
	ModelScoped      bool            `json:"model_scoped,omitempty"`
	RemainingPercent *float64        `json:"remaining_percent,omitempty"`
	Exhausted        bool            `json:"exhausted"`
	ResetAt          *time.Time      `json:"reset_at,omitempty"`
}

// QuotaRoutingAccountStatus explains whether a credential can take a new session.
// Credentials are identified only by auth index so no secrets or emails are exposed.
type QuotaRoutingAccountStatus struct {
	AuthIndex string `json:"auth_index"`
	Provider  string `json:"provider"`
	Priority  int    `json:"priority"`
	Eligible  bool   `json:"eligible"`
	// Rank is the 1-based order in which eligible credentials receive new sessions.
	Rank           int                        `json:"rank,omitempty"`
	Reason         string                     `json:"reason"`
	Tier           QuotaRoutingTier           `json:"tier,omitempty"`
	RankingWindow  string                     `json:"ranking_window,omitempty"`
	RankingResetAt *time.Time                 `json:"ranking_reset_at,omitempty"`
	BlockingWindow string                     `json:"blocking_window,omitempty"`
	BlockedUntil   *time.Time                 `json:"blocked_until,omitempty"`
	ObservedAt     *time.Time                 `json:"observed_at,omitempty"`
	Stale          bool                       `json:"stale"`
	Windows        []QuotaRoutingWindowStatus `json:"windows"`
}

// RoutingDecisionCandidateStatus is a management view of a decision candidate.
type RoutingDecisionCandidateStatus struct {
	AuthIndex      string           `json:"auth_index"`
	Tier           QuotaRoutingTier `json:"tier"`
	Reason         string           `json:"reason"`
	RankingWindow  string           `json:"ranking_window,omitempty"`
	RankingResetAt *time.Time       `json:"ranking_reset_at,omitempty"`
	BlockingWindow string           `json:"blocking_window,omitempty"`
	BlockedUntil   *time.Time       `json:"blocked_until,omitempty"`
}

// RoutingDecisionStatus is a management view of a recorded decision.
type RoutingDecisionStatus struct {
	At                time.Time                        `json:"at"`
	Kind              string                           `json:"kind"`
	Provider          string                           `json:"provider"`
	Model             string                           `json:"model,omitempty"`
	SelectedAuthIndex string                           `json:"selected_auth_index,omitempty"`
	PreviousAuthIndex string                           `json:"previous_auth_index,omitempty"`
	Repeat            int                              `json:"repeat"`
	Candidates        []RoutingDecisionCandidateStatus `json:"candidates"`
}

// QuotaRoutingReport is the management snapshot for the soonest-quota-reset strategy.
type QuotaRoutingReport struct {
	Active            bool                        `json:"active"`
	EvaluatedAt       time.Time                   `json:"evaluated_at"`
	Provider          string                      `json:"provider,omitempty"`
	Model             string                      `json:"model,omitempty"`
	StaleAfterSeconds int64                       `json:"stale_after_seconds"`
	Accounts          []QuotaRoutingAccountStatus `json:"accounts"`
	Decisions         []RoutingDecisionStatus     `json:"decisions"`
}

// QuotaRoutingReport evaluates every credential the way a new session would see it.
// It is read-only: it never selects, binds, or mutates credential state.
// An empty provider includes all providers; an empty model evaluates credential-level
// quota only, so model-scoped windows and model support are not considered.
func (m *Manager) QuotaRoutingReport(provider, model string) QuotaRoutingReport {
	now := time.Now()
	report := QuotaRoutingReport{
		EvaluatedAt:       now,
		Provider:          strings.TrimSpace(provider),
		Model:             canonicalModelKey(model),
		StaleAfterSeconds: int64(QuotaObservationMaxAge / time.Second),
		Accounts:          []QuotaRoutingAccountStatus{},
		Decisions:         []RoutingDecisionStatus{},
	}
	if m == nil {
		return report
	}
	providerKey := canonicalSchedulingProvider(report.Provider)
	registryRef := registry.GetGlobalRegistry()

	m.mu.RLock()
	selector := soonestQuotaResetSelectorOf(m.selector)
	report.Active = selector != nil
	indexByID := make(map[string]string, len(m.auths))
	var rankable []rankedQuotaCandidate
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		indexByID[auth.ID] = safeAuthIndex(auth)
		if providerKey != "" && canonicalSchedulingProvider(executorKeyFromAuth(auth)) != providerKey {
			continue
		}
		status, evaluation, eligible := m.quotaRoutingAccountStatusLocked(registryRef, auth, report.Model, now)
		report.Accounts = append(report.Accounts, status)
		if eligible {
			rankable = append(rankable, rankedQuotaCandidate{auth: auth, evaluation: evaluation})
		}
	}
	m.mu.RUnlock()

	assignQuotaRoutingRanks(report.Accounts, rankable)
	sort.SliceStable(report.Accounts, func(i, j int) bool {
		left, right := report.Accounts[i], report.Accounts[j]
		if left.Provider != right.Provider {
			return left.Provider < right.Provider
		}
		if left.Eligible != right.Eligible {
			return left.Eligible
		}
		if left.Rank != right.Rank {
			return left.Rank < right.Rank
		}
		return left.AuthIndex < right.AuthIndex
	})

	if selector != nil {
		for _, decision := range selector.Decisions() {
			report.Decisions = append(report.Decisions, routingDecisionStatus(decision, indexByID))
		}
	}
	return report
}

// quotaRoutingAccountStatusLocked applies the same pre-selection checks the manager uses,
// then the quota evaluation. Caller must hold m.mu.
func (m *Manager) quotaRoutingAccountStatusLocked(registryRef *registry.ModelRegistry, auth *Auth, model string, now time.Time) (QuotaRoutingAccountStatus, QuotaRoutingEvaluation, bool) {
	status := QuotaRoutingAccountStatus{
		AuthIndex: safeAuthIndex(auth),
		Provider:  strings.TrimSpace(auth.Provider),
		Priority:  authPriority(auth),
		Windows:   []QuotaRoutingWindowStatus{},
	}
	checkModel := ""
	if model != "" {
		checkModel = m.selectionModelForAuth(auth, model)
	}
	evaluation := EvaluateQuotaForRouting(auth, checkModel, now)
	status.Tier = evaluation.Tier
	status.Reason = evaluation.Reason
	status.RankingWindow = evaluation.RankingWindow
	status.RankingResetAt = optionalTime(evaluation.RankingResetAt)
	status.BlockingWindow = evaluation.BlockingWindow
	status.BlockedUntil = optionalTime(evaluation.BlockedUntil)
	status.ObservedAt = optionalTime(evaluation.ObservedAt)
	status.Stale = evaluation.Stale
	for _, window := range evaluation.Windows {
		windowStatus := QuotaRoutingWindowStatus{
			Name:        window.Name,
			Kind:        window.Kind,
			ModelScoped: window.ModelScoped,
			Exhausted:   window.Exhausted,
			ResetAt:     optionalTime(window.ResetAt),
		}
		if remaining, ok := window.RemainingPercent(); ok {
			windowStatus.RemainingPercent = &remaining
		}
		status.Windows = append(status.Windows, windowStatus)
	}

	exclusion := ""
	var blockedUntil time.Time
	switch {
	case auth.Disabled || auth.Status == StatusDisabled:
		exclusion = RoutingExclusionDisabled
	case hasUnauthorizedAuthFailure(auth):
		exclusion = RoutingExclusionInvalidCredentials
	case model != "" && !m.authSupportsRouteModel(registryRef, auth, model):
		exclusion = RoutingExclusionModelUnsupported
	default:
		if blocked, reason, next := isAuthBlockedForModel(auth, checkModel, now); blocked {
			switch reason {
			case blockReasonDisabled:
				exclusion = RoutingExclusionDisabled
			case blockReasonCooldown:
				exclusion = RoutingExclusionCooldown
				blockedUntil = next
			default:
				exclusion = RoutingExclusionInvalidCredentials
				if next.After(now) {
					exclusion = RoutingExclusionCooldown
					blockedUntil = next
				}
			}
		}
	}
	if exclusion != "" {
		status.Reason = exclusion
		if !blockedUntil.IsZero() {
			status.BlockedUntil = optionalTime(blockedUntil)
		}
		return status, evaluation, false
	}
	status.Eligible = evaluation.Tier != QuotaTierExhausted
	return status, evaluation, status.Eligible
}

// assignQuotaRoutingRanks orders eligible credentials the way the selector would for a
// new session: highest priority tier first, then the soonest-quota-reset order. Ranks
// restart per provider because a session never moves between providers.
func assignQuotaRoutingRanks(accounts []QuotaRoutingAccountStatus, rankable []rankedQuotaCandidate) {
	sort.SliceStable(rankable, func(i, j int) bool {
		left, right := rankable[i], rankable[j]
		if left.auth.Provider != right.auth.Provider {
			return left.auth.Provider < right.auth.Provider
		}
		if pi, pj := authPriority(left.auth), authPriority(right.auth); pi != pj {
			return pi > pj
		}
		if left.evaluation.Tier != right.evaluation.Tier {
			return quotaTierOrder[left.evaluation.Tier] < quotaTierOrder[right.evaluation.Tier]
		}
		if left.evaluation.Tier == QuotaTierRanked && !left.evaluation.RankingResetAt.Equal(right.evaluation.RankingResetAt) {
			return left.evaluation.RankingResetAt.Before(right.evaluation.RankingResetAt)
		}
		return left.auth.ID < right.auth.ID
	})
	rankByIndex := make(map[string]int, len(rankable))
	rank := 0
	for i, candidate := range rankable {
		if i == 0 || candidate.auth.Provider != rankable[i-1].auth.Provider {
			rank = 0
		}
		rank++
		rankByIndex[safeAuthIndex(candidate.auth)] = rank
	}
	for i := range accounts {
		if accounts[i].Eligible {
			accounts[i].Rank = rankByIndex[accounts[i].AuthIndex]
		}
	}
}

func routingDecisionStatus(decision RoutingDecision, indexByID map[string]string) RoutingDecisionStatus {
	status := RoutingDecisionStatus{
		At:                decision.At,
		Kind:              decision.Kind,
		Provider:          decision.Provider,
		Model:             decision.Model,
		SelectedAuthIndex: indexByID[decision.SelectedAuthID],
		PreviousAuthIndex: indexByID[decision.PreviousAuthID],
		Repeat:            decision.Repeat,
		Candidates:        make([]RoutingDecisionCandidateStatus, 0, len(decision.Candidates)),
	}
	for _, candidate := range decision.Candidates {
		index, ok := indexByID[candidate.AuthID]
		if !ok {
			// The credential was removed since the decision; never fall back to its raw ID.
			continue
		}
		status.Candidates = append(status.Candidates, RoutingDecisionCandidateStatus{
			AuthIndex:      index,
			Tier:           candidate.Tier,
			Reason:         candidate.Reason,
			RankingWindow:  candidate.RankingWindow,
			RankingResetAt: optionalTime(candidate.RankingResetAt),
			BlockingWindow: candidate.BlockingWindow,
			BlockedUntil:   optionalTime(candidate.BlockedUntil),
		})
	}
	return status
}

// safeAuthIndex returns the stable auth index without mutating shared state.
func safeAuthIndex(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if index := strings.TrimSpace(auth.Index); index != "" {
		return index
	}
	return stableAuthIndex(auth.indexSeed())
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}
