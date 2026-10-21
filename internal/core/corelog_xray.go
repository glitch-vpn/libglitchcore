//go:build !no_xray

package core

import (
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	xrayAppLog "github.com/xtls/xray-core/app/log"
	xrayCommonLog "github.com/xtls/xray-core/common/log"
	_ "github.com/xtls/xray-core/main/distro/all" // registers all xray protocols/transports
)

func registerCoreLogHandler() {
	if err := xrayAppLog.RegisterHandlerCreator(
		xrayAppLog.LogType_Console,
		func(xrayAppLog.LogType, xrayAppLog.HandlerCreatorOptions) (xrayCommonLog.Handler, error) {
			return xrayLogHandler{}, nil
		},
	); err != nil {
		logfmt.Errorf("[Xray] register log handler: %v", err)
	}
}

// xrayLogHandler takes xray's messages typed, so a line keeps the severity
// xray gave it. With MaskAddress set xray hands every message over wrapped:
// the wrapper's text is the masked one, and the inspector reads the
// unmasked access record inside.
type xrayLogHandler struct{}

func (xrayLogHandler) Handle(msg xrayCommonLog.Message) {
	inner := msg
	if masked, ok := msg.(*xrayAppLog.MaskedMsgWrapper); ok {
		inner = masked.Message
	}
	switch m := inner.(type) {
	case *xrayCommonLog.AccessMessage:
		handleXrayAccess(m)
	case *xrayCommonLog.GeneralMessage:
		level := xrayMessageLevel(m.Severity)
		if !logEnabled(level) {
			return
		}
		text := strings.TrimPrefix(msg.String(), "["+m.Severity.String()+"] ")
		emitLog(level, "Xray", text)
	}
}

func handleXrayAccess(m *xrayCommonLog.AccessMessage) {
	a, ok := logfmt.ParseAccess(m.String())
	if !ok || globalController == nil {
		return
	}
	globalController.emitConn(conninspect.Record{
		Engine:   "xray",
		Src:      a.Src,
		Status:   a.Status,
		Network:  a.Network,
		Host:     a.Host,
		Port:     a.Port,
		Inbound:  a.Inbound,
		Outbound: a.Outbound,
	})
}

func xrayMessageLevel(s xrayCommonLog.Severity) logfmt.Level {
	switch s {
	case xrayCommonLog.Severity_Error:
		return logfmt.Error
	case xrayCommonLog.Severity_Warning:
		return logfmt.Warn
	case xrayCommonLog.Severity_Debug:
		return logfmt.Debug
	default:
		return logfmt.Info
	}
}
