// Package conninspect defines the ConnEvent wire shape shared by all engines.
package conninspect

import (
	"encoding/json"
	"time"
)

// Record is one routed connection.
// Outbound is the routing outcome; Rule is set when the engine exposes it (mihomo).
type Record struct {
	Engine   string `json:"engine,omitempty"`
	Src      string `json:"src,omitempty"`
	Status   string `json:"status,omitempty"` // accepted | rejected
	Network  string `json:"network,omitempty"`
	Host     string `json:"host"`
	Port     string `json:"port,omitempty"`
	Inbound  string `json:"inbound,omitempty"`
	Outbound string `json:"outbound,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// JSON is the ConnEvent (402) payload; "" on marshal failure.
func (r Record) JSON() string {
	entry := struct {
		Ts string `json:"ts"`
		Record
	}{Ts: time.Now().UTC().Format(time.RFC3339Nano), Record: r}
	b, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	return string(b)
}
