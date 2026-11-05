package routing

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// TargetsVersion is the only version of the targets intent the core reads.
const TargetsVersion = 1

// Caps on what one session carries.
const (
	MaxTargetServers = 64
	MaxTargetGroups  = 16
	MaxTargetChains  = 16
	MaxChainHops     = 4
	MinChainHops     = 2
)

var targetIDPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// Targets are the named outcomes a tier's routes can name. The ids are the
// caller's, unique across all three kinds for the session, and the core never
// sees a display name.
type Targets struct {
	Version int            `json:"version"`
	Servers []TargetServer `json:"servers,omitempty"`
	Groups  []TargetGroup  `json:"groups,omitempty"`
	Chains  []TargetChain  `json:"chains,omitempty"`
}

// TargetServer is one server a route, a group or a chain can name.
type TargetServer struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

// TargetGroup balances over servers with the session's strategy.
type TargetGroup struct {
	ID      string   `json:"id"`
	Servers []string `json:"servers"`
}

// TargetChain dials its first hop directly and each later hop through the one
// before it; the last hop exits.
type TargetChain struct {
	ID   string   `json:"id"`
	Hops []string `json:"hops"`
}

// Route sends the flows its matchers match to the target To names.
type Route struct {
	To    string   `json:"to"`
	Match []string `json:"match"`
}

// TargetKind says what an id names.
type TargetKind int

const (
	KindServerTarget TargetKind = iota + 1
	KindGroupTarget
	KindChainTarget
)

// Kind reports what id names; a nil Targets names nothing.
func (t *Targets) Kind(id string) (TargetKind, bool) {
	if t == nil {
		return 0, false
	}
	for _, s := range t.Servers {
		if s.ID == id {
			return KindServerTarget, true
		}
	}
	for _, g := range t.Groups {
		if g.ID == id {
			return KindGroupTarget, true
		}
	}
	for _, c := range t.Chains {
		if c.ID == id {
			return KindChainTarget, true
		}
	}
	return 0, false
}

// Link is the link of the server id, "" when there is none.
func (t *Targets) Link(id string) string {
	if t != nil {
		for _, s := range t.Servers {
			if s.ID == id {
				return s.Link
			}
		}
	}
	return ""
}

// Validate refuses what the engines would misread: a version it does not know,
// an id twice or malformed, an empty group or chain, a chain out of bounds or
// naming a hop twice, a member that is no server, and a count over a cap.
func (t *Targets) Validate() error {
	if t == nil {
		return nil
	}
	if t.Version != TargetsVersion {
		return fmt.Errorf("targets: version %d is not supported", t.Version)
	}
	if len(t.Servers) > MaxTargetServers {
		return fmt.Errorf("targets: more than %d servers", MaxTargetServers)
	}
	if len(t.Groups) > MaxTargetGroups {
		return fmt.Errorf("targets: more than %d groups", MaxTargetGroups)
	}
	if len(t.Chains) > MaxTargetChains {
		return fmt.Errorf("targets: more than %d chains", MaxTargetChains)
	}
	seen := map[string]bool{}
	claim := func(id string) error {
		switch {
		case !targetIDPattern.MatchString(id):
			return fmt.Errorf("targets: id %q must be 1-16 characters of a-z and 0-9", id)
		case seen[id]:
			return fmt.Errorf("targets: duplicate id %q", id)
		}
		seen[id] = true
		return nil
	}
	servers := map[string]bool{}
	for _, s := range t.Servers {
		if err := claim(s.ID); err != nil {
			return err
		}
		if strings.TrimSpace(s.Link) == "" {
			return fmt.Errorf("targets: server %q has no link", s.ID)
		}
		servers[s.ID] = true
	}
	for _, g := range t.Groups {
		if err := claim(g.ID); err != nil {
			return err
		}
		if len(g.Servers) == 0 {
			return fmt.Errorf("targets: group %q is empty", g.ID)
		}
		for _, m := range g.Servers {
			if !servers[m] {
				return fmt.Errorf("targets: group %q names unknown server %q", g.ID, m)
			}
		}
	}
	for _, c := range t.Chains {
		if err := claim(c.ID); err != nil {
			return err
		}
		if len(c.Hops) < MinChainHops || len(c.Hops) > MaxChainHops {
			return fmt.Errorf("targets: chain %q has %d hops, want %d..%d", c.ID, len(c.Hops), MinChainHops, MaxChainHops)
		}
		hopSeen := map[string]bool{}
		for _, h := range c.Hops {
			switch {
			case !servers[h]:
				return fmt.Errorf("targets: chain %q names unknown server %q", c.ID, h)
			case hopSeen[h]:
				return fmt.Errorf("targets: chain %q names server %q twice", c.ID, h)
			}
			hopSeen[h] = true
		}
	}
	return nil
}

var errRouteProcess = errors.New("a route cannot match a process: it names no site")

func (p Profile) validateRoutes() error {
	for i, t := range p.Tiers {
		for _, r := range t.Routes {
			if _, ok := p.Targets.Kind(r.To); !ok {
				return fmt.Errorf("tier %d: route names undefined id %q", i+1, r.To)
			}
			for _, m := range r.Match {
				if err := validateMatcher(m); err != nil {
					return fmt.Errorf("tier %d: %q: %w", i+1, m, err)
				}
				if kind, _, ok := Classify(m); ok && kind == KindProcess {
					return fmt.Errorf("tier %d: %q: %w", i+1, m, errRouteProcess)
				}
			}
		}
	}
	return nil
}
