package auth

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QuotaObservationMaxAge is how long a passive quota snapshot is trusted for ranking.
// Older snapshots fall back to deterministic ordering because remaining allowance may
// have changed since the snapshot was taken.
const QuotaObservationMaxAge = time.Hour

// longQuotaWindowThreshold separates short rolling windows (5h, daily) from the
// weekly/model-specific windows used as the soonest-reset ranking key.
const longQuotaWindowThreshold = 24 * time.Hour

const (
	quotaPercentMax         = 100.0
	minutesPerDay           = 24 * 60
	claudeUtilizationScale  = 100.0
	devinPercentSuffix      = "%"
	claudeSignalPrefix      = "anthropic-ratelimit-unified-"
	codexSignalPrefix       = "x-codex-"
	codexAdditionalPrefix   = "additional-"
	codexCodeReviewLimitKey = "code-review"
	codexBaseLimitID        = "codex"
	codexActiveLimitSignal  = codexSignalPrefix + "active-limit"
	codexLimitReachedSuffix = "limit-reached"
	codexLimitNameSuffix    = "limit-name"
	codexSignalTrue         = "true"
)

// QuotaWindowKind classifies a provider quota window.
type QuotaWindowKind string

const (
	// QuotaWindowShort is a short rolling window such as Claude 5h, Codex primary, or Devin daily.
	QuotaWindowShort QuotaWindowKind = "short"
	// QuotaWindowLong is a weekly or model-specific window used as the ranking key.
	QuotaWindowLong QuotaWindowKind = "long"
)

// QuotaWindow is one provider quota window normalized from passive signals.
// Values are only ever copied from provider data: a window without a reported
// usage or reset time keeps those fields empty instead of guessing.
type QuotaWindow struct {
	Name        string          `json:"name"`
	Kind        QuotaWindowKind `json:"kind"`
	ModelScoped bool            `json:"model_scoped,omitempty"`
	// LimitName is the provider's name for a Codex additional limit, such as a model name.
	LimitName string `json:"limit_name,omitempty"`
	// ActiveLimit reports that Codex named this window's limit as the one metering the response.
	ActiveLimit bool `json:"active_limit,omitempty"`
	// UsedPercent is nil when the provider did not report usage for this window.
	UsedPercent *float64  `json:"used_percent,omitempty"`
	Exhausted   bool      `json:"exhausted"`
	ResetAt     time.Time `json:"reset_at,omitempty"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
}

// RemainingPercent returns the remaining allowance when usage is known.
func (w QuotaWindow) RemainingPercent() (float64, bool) {
	if w.UsedPercent == nil {
		return 0, false
	}
	return math.Max(0, quotaPercentMax-*w.UsedPercent), true
}

// parseQuotaWindows normalizes one passive snapshot for the given provider.
// Unsupported providers and unrecognized signals yield no windows.
func parseQuotaWindows(provider string, quota QuotaState) []QuotaWindow {
	if len(quota.Signals) == 0 {
		return nil
	}
	signals := make(map[string]string, len(quota.Signals))
	for key, value := range quota.Signals {
		signals[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	var windows []QuotaWindow
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		windows = parseClaudeQuotaWindows(signals)
	case "codex":
		windows = parseCodexQuotaWindows(signals, quota.ObservedAt)
	case "devin":
		windows = parseDevinQuotaWindows(signals)
	default:
		return nil
	}
	for i := range windows {
		windows[i].ObservedAt = quota.ObservedAt
	}
	sort.SliceStable(windows, func(i, j int) bool { return windows[i].Name < windows[j].Name })
	return windows
}

// claudeQuotaWindowSpecs lists the Anthropic unified windows. 7d_oi is a model-specific
// weekly window, so it only applies when observed on the requested model's own responses.
var claudeQuotaWindowSpecs = []struct {
	name        string
	kind        QuotaWindowKind
	modelScoped bool
}{
	{name: "5h", kind: QuotaWindowShort},
	{name: "7d", kind: QuotaWindowLong},
	{name: "7d_oi", kind: QuotaWindowLong, modelScoped: true},
}

func parseClaudeQuotaWindows(signals map[string]string) []QuotaWindow {
	windows := make([]QuotaWindow, 0, len(claudeQuotaWindowSpecs))
	for _, spec := range claudeQuotaWindowSpecs {
		prefix := claudeSignalPrefix + spec.name + "-"
		status := strings.ToLower(signals[prefix+"status"])
		rawUtilization, hasUtilization := signals[prefix+"utilization"]
		rawReset, hasReset := signals[prefix+"reset"]
		if status == "" && !hasUtilization && !hasReset {
			continue
		}
		window := QuotaWindow{Name: spec.name, Kind: spec.kind, ModelScoped: spec.modelScoped}
		if utilization, ok := parseFiniteFloat(rawUtilization); ok && utilization >= 0 {
			used := utilization * claudeUtilizationScale
			window.UsedPercent = &used
		}
		if resetAt, ok := parseQuotaResetTime(rawReset); ok {
			window.ResetAt = resetAt
		}
		window.Exhausted = status == "rejected" || (window.UsedPercent != nil && *window.UsedPercent >= quotaPercentMax)
		windows = append(windows, window)
	}
	return windows
}

// codexWindowUsedPattern matches every Codex window usage signal. The optional limit
// namespace is empty for the base limit, "additional-<name>" on the websocket path, or
// a short limit name on the HTTP path.
var codexWindowUsedPattern = regexp.MustCompile(`^x-codex-(?:(.+)-)?(primary|secondary)-used-percent$`)

func parseCodexQuotaWindows(signals map[string]string, observedAt time.Time) []QuotaWindow {
	var windows []QuotaWindow
	mostUsedByLimit := make(map[string]int)
	for key, rawUsed := range signals {
		match := codexWindowUsedPattern.FindStringSubmatch(key)
		if match == nil {
			continue
		}
		limit, slot := match[1], match[2]
		if limit == codexCodeReviewLimitKey {
			// Code review limits never apply to model requests.
			continue
		}
		used, ok := parseFiniteFloat(rawUsed)
		if !ok || used < 0 {
			continue
		}
		limitPrefix := codexSignalPrefix
		name := slot
		if limit != "" {
			limitPrefix = codexSignalPrefix + limit + "-"
			name = strings.TrimPrefix(limit, codexAdditionalPrefix) + ":" + slot
		}
		prefix := limitPrefix + slot + "-"
		window := QuotaWindow{
			Name:        name,
			Kind:        codexWindowKind(slot, signals[prefix+"window-minutes"]),
			ModelScoped: limit != "",
			UsedPercent: &used,
			Exhausted:   used >= quotaPercentMax,
		}
		if limit != "" {
			window.LimitName = signals[limitPrefix+codexLimitNameSuffix]
			if window.LimitName == "" {
				window.LimitName = strings.TrimPrefix(limit, codexAdditionalPrefix)
			}
			window.ActiveLimit = codexLimitIsActive(signals[codexActiveLimitSignal], limit)
		}
		if resetAt, okReset := parseQuotaResetTime(signals[prefix+"reset-at"]); okReset {
			window.ResetAt = resetAt
		} else if seconds, okAfter := parseFiniteFloat(signals[prefix+"reset-after-seconds"]); okAfter && seconds >= 0 && !observedAt.IsZero() {
			window.ResetAt = observedAt.Add(time.Duration(seconds * float64(time.Second)))
		}
		windows = append(windows, window)

		// Remember the most consumed window of each limit that Codex reports as reached.
		if !strings.EqualFold(signals[limitPrefix+codexLimitReachedSuffix], codexSignalTrue) {
			continue
		}
		index := len(windows) - 1
		if previous, found := mostUsedByLimit[limit]; !found || used > *windows[previous].UsedPercent ||
			(used == *windows[previous].UsedPercent && window.ResetAt.After(windows[previous].ResetAt)) {
			mostUsedByLimit[limit] = index
		}
	}
	// A reached limit is exhausted even when the rounded percentages stay below 100.
	// The most consumed window is the one blocking it.
	for _, index := range mostUsedByLimit {
		windows[index].Exhausted = true
	}
	return windows
}

// codexLimitIsActive reports whether the active-limit signal names the given limit
// namespace. Codex reports limit IDs such as "codex_bengalfox" while header namespaces
// drop the "codex" prefix ("bengalfox") or carry the limit name ("additional-<name>").
func codexLimitIsActive(activeLimit, namespace string) bool {
	normalize := func(value string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "_", "-")
	}
	active := normalize(activeLimit)
	if active == "" {
		return false
	}
	namespace = strings.TrimPrefix(normalize(namespace), codexAdditionalPrefix)
	return active == namespace || active == codexBaseLimitID+"-"+namespace
}

// codexWindowKind classifies by the reported window length. Without a length, Codex's
// documented layout applies: primary is the short window, secondary the weekly one.
func codexWindowKind(slot, rawMinutes string) QuotaWindowKind {
	if minutes, ok := parseFiniteFloat(rawMinutes); ok && minutes > 0 {
		if minutes > minutesPerDay {
			return QuotaWindowLong
		}
		return QuotaWindowShort
	}
	if slot == "secondary" {
		return QuotaWindowLong
	}
	return QuotaWindowShort
}

func parseDevinQuotaWindows(signals map[string]string) []QuotaWindow {
	windows := make([]QuotaWindow, 0, 2)
	for _, spec := range []struct {
		name string
		kind QuotaWindowKind
	}{
		{name: "daily", kind: QuotaWindowShort},
		{name: "weekly", kind: QuotaWindowLong},
	} {
		rawRemaining, hasRemaining := signals[spec.name+"_quota_remaining_percent"]
		rawReset, hasReset := signals[spec.name+"_quota_reset_at"]
		if !hasRemaining && !hasReset {
			continue
		}
		window := QuotaWindow{Name: spec.name, Kind: spec.kind}
		if remaining, ok := parseFiniteFloat(strings.TrimSuffix(rawRemaining, devinPercentSuffix)); ok {
			used := quotaPercentMax - remaining
			window.UsedPercent = &used
			window.Exhausted = remaining <= 0
		}
		if resetAt, ok := parseQuotaResetTime(rawReset); ok {
			window.ResetAt = resetAt
		}
		windows = append(windows, window)
	}
	return windows
}

func parseFiniteFloat(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, errParse := strconv.ParseFloat(raw, 64)
	if errParse != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

// parseQuotaResetTime accepts unix seconds (Anthropic, Codex) or RFC3339 (Devin).
func parseQuotaResetTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if seconds, errParse := strconv.ParseInt(raw, 10, 64); errParse == nil {
		if seconds <= 0 {
			return time.Time{}, false
		}
		return time.Unix(seconds, 0), true
	}
	if parsed, errParse := time.Parse(time.RFC3339, raw); errParse == nil {
		return parsed, true
	}
	return time.Time{}, false
}
