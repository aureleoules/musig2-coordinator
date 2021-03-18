package coordinator

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.DisableCaller = true
	logger, err := config.Build()
	if err != nil {
		zap.S().Panic(err)
	}

	zap.ReplaceGlobals(logger)
}
