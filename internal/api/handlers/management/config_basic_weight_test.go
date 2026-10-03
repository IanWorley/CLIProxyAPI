package management

import "testing"

func TestNormalizeRoutingStrategyWeightedRoundRobin(t *testing.T) {
	for _, input := range []string{"weighted-round-robin", "weightedroundrobin", "wrr"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "weighted-round-robin" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want weighted-round-robin, true", input, got, ok)
		}
	}
}

func TestNormalizeRoutingStrategySoonestQuotaReset(t *testing.T) {
	for _, input := range []string{"soonest-quota-reset", "SoonestQuotaReset", "sqr"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "soonest-quota-reset" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want soonest-quota-reset, true", input, got, ok)
		}
	}
}
