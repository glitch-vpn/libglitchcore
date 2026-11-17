package mihomoconfig

import (
	"sort"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// processFirstRules are the rules of the apps a profile names by process, for
// a TUN on which mihomo reads the app behind each flow. They follow the order
// the tun2socks bridge gave those apps, whatever tier holds the entry:
// block, then direct, then proxy. A blocked app is refused at once. An app
// sent direct meets every tier's block, then goes direct; an app sent to the
// proxy meets them and the local networks, then goes to the proxy, in every
// mode. The sub-rules hold what those flows go through.
func processFirstRules(p routing.Profile, target string) (rules []string, subRules map[string][]string) {
	byTarget := map[string][]string{}
	for name, outcome := range routing.ProcessRules(p) {
		byTarget[outcome] = append(byTarget[outcome], name)
	}
	subRules = map[string][]string{}
	if condition := anyProcess(byTarget[routing.TargetBlock]); condition != "" {
		rules = append(rules, condition+",REJECT")
	}
	if condition := anyProcess(byTarget[routing.TargetDirect]); condition != "" {
		if p.HasBlock() {
			rules = append(rules, "SUB-RULE,("+condition+"),"+DirectFlowsSubRule)
			subRules[DirectFlowsSubRule] = directFlowRules(p)
		} else {
			rules = append(rules, condition+",DIRECT")
		}
	}
	if condition := anyProcess(byTarget[routing.TargetProxy]); condition != "" {
		if forceFlowsNeedSubRule(p) {
			rules = append(rules, "SUB-RULE,("+condition+"),"+forceFlowsSubRule)
			subRules[forceFlowsSubRule] = forceFlowRules(p, target)
		} else {
			rules = append(rules, condition+","+target)
		}
		// mihomo moves on from a matched rule whose proxy lacks UDP.
		rules = append(rules, condition+",REJECT")
	}
	return rules, subRules
}

// anyProcess is the condition a flow meets when its app is one of names, as a
// rule head; "" for none.
func anyProcess(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	operands := make([]string, len(names))
	for i, name := range names {
		operands[i] = "(" + processCondition(name) + ")"
	}
	if len(operands) == 1 {
		return processCondition(names[0])
	}
	return "OR,(" + strings.Join(operands, ",") + ")"
}
