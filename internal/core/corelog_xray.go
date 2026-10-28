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

// Before the first xray instance exists, xray logs through a default handler
// that writes raw stdout whatever the verbosity: the geodata reload and the
// config build run then, and again after an instance closes, which leaves
// its own handler registered. The core's handler is registered at
// initialization and after each instance.
func registerCoreLogHandler() {
	xrayCommonLog.RegisterHandler(xrayLogHandler{})
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

// What MaskAddress "half" keeps of an address; a line xray writes outside an
// instance, with no config to say, is masked the same way as one inside.
const (
	halfMaskIPv4 = 16
	halfMaskIPv6 = 32
)

func (xrayLogHandler) Handle(msg xrayCommonLog.Message) {
	masked, ok := msg.(*xrayAppLog.MaskedMsgWrapper)
	if !ok {
		masked = &xrayAppLog.MaskedMsgWrapper{Message: msg, Mask4: halfMaskIPv4, Mask6: halfMaskIPv6}
		msg = masked
	}
	inner := masked.Message
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

// xray records every connection whatever the config says.
func handleXrayAccess(m *xrayCommonLog.AccessMessage) {
	if !connInspectEnabled.Load() {
		return
	}
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
