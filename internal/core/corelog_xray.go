//go:build !no_xray

package core

import (
	"log"
	"os"

	xrayAppLog "github.com/xtls/xray-core/app/log"
	xrayCommonLog "github.com/xtls/xray-core/common/log"
	_ "github.com/xtls/xray-core/main/distro/all" // registers all xray protocols/transports
)

func registerCoreLogHandler() {
	if err := xrayAppLog.RegisterHandlerCreator(
		xrayAppLog.LogType_Console,
		func(lt xrayAppLog.LogType, options xrayAppLog.HandlerCreatorOptions) (xrayCommonLog.Handler, error) {
			return xrayCommonLog.NewLogger(createLogWriter()), nil
		},
	); err != nil {
		log.Printf("Failed to register log handler: %v", err)
	}
}

// Timestamps off - our JSON already carries ts.
type logWriter struct {
	logger *log.Logger
}

func (w *logWriter) Write(s string) error {
	handleCoreLogLine(s)
	return nil
}

func (w *logWriter) Close() error { return nil }

func createLogWriter() xrayCommonLog.WriterCreator {
	return func() xrayCommonLog.Writer {
		return &logWriter{logger: log.New(os.Stdout, "", 0)}
	}
}
