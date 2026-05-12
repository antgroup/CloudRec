// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"context"
	"github.com/core-sdk/constant"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"regexp"
)

// NewLogger
/**
* 获取日志
* filePath 日志文件路径
* level 日志级别
* maxSize 每个日志文件保存的最大尺寸 单位：M
* maxBackups 日志文件最多保存多少个备份
* maxAge 文件最多保存多少天
* compress 是否压缩
 */
func NewLogger(filePath string, level zapcore.Level, maxSize int, maxBackups int, maxAge int, compress bool) *zap.Logger {
	core := newCore(filePath, level, maxSize, maxBackups, maxAge, compress)
	core = redactingCore{Core: core}
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
}

func newCore(filePath string, level zapcore.Level, maxSize int, maxBackups int, maxAge int, compress bool) zapcore.Core {
	hook := lumberjack.Logger{
		Filename:   filePath,   // 日志文件路径
		MaxSize:    maxSize,    // 每个日志文件保存的最大尺寸 单位：M
		MaxBackups: maxBackups, // 日志文件最多保存多少个备份
		MaxAge:     maxAge,     // 文件最多保存多少天
		Compress:   compress,   // 是否压缩
	}
	// 设置日志级别
	atomicLevel := zap.NewAtomicLevel()
	atomicLevel.SetLevel(level)
	//公用编码器
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseColorLevelEncoder, // 小写编码器
		EncodeTime:     zapcore.ISO8601TimeEncoder,         // ISO8601 UTC 时间格式
		EncodeDuration: zapcore.SecondsDurationEncoder,     //
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	return zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),                                        // 编码器配置
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(&hook)), // 打印到控制台和文件
		atomicLevel, // 日志级别
	)
}

type redactingCore struct {
	zapcore.Core
}

func (c redactingCore) With(fields []zapcore.Field) zapcore.Core {
	return redactingCore{Core: c.Core.With(redactLogFields(fields))}
}

func (c redactingCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c redactingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	entry.Message = redactLogText(entry.Message)
	return c.Core.Write(entry, redactLogFields(fields))
}

func redactLogFields(fields []zapcore.Field) []zapcore.Field {
	if len(fields) == 0 {
		return nil
	}
	redacted := make([]zapcore.Field, len(fields))
	copy(redacted, fields)
	for i := range redacted {
		switch redacted[i].Type {
		case zapcore.StringType:
			redacted[i].String = redactLogText(redacted[i].String)
		case zapcore.ErrorType:
			if err, ok := redacted[i].Interface.(error); ok && err != nil {
				redacted[i] = zap.String(redacted[i].Key, redactLogText(err.Error()))
			}
		}
	}
	return redacted
}

var logRedactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(AccessKeyId=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(AccessKeySecret=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(SecurityToken=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(Signature=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(SignatureNonce=)[^&\s"']+`),
	regexp.MustCompile(`(?i)("AccessKeyId"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("AccessKeySecret"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("SecurityToken"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("Signature"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)\bLTAI[0-9A-Za-z]{12,}\b`),
}

func redactLogText(value string) string {
	redacted := value
	for _, pattern := range logRedactionPatterns {
		redacted = pattern.ReplaceAllString(redacted, `${1}<redacted>`)
	}
	return redacted
}

var logger *zap.Logger

func GetWLogger() *zap.Logger {
	return logger
}

func SetWLogger(next *zap.Logger) {
	if next == nil {
		return
	}
	if logger != nil {
		_ = logger.Sync()
	}
	logger = next
}

func init() {
	logger = NewLogger("./logs/task.log", zapcore.InfoLevel, 256, 30, 7, true)
}

func fieldsFromContext(ctx context.Context) []zap.Field {
	var fields []zap.Field

	if resourceType, ok := ctx.Value(constant.TraceId).(string); ok {
		fields = append(fields, zap.String(string(constant.TraceId), resourceType))
	}
	if regionId, ok := ctx.Value(constant.RegionId).(string); ok {
		fields = append(fields, zap.String(string(constant.RegionId), regionId))
	}

	if cloudAccountId, ok := ctx.Value(constant.CloudAccountId).(string); ok {
		fields = append(fields, zap.String(string(constant.CloudAccountId), cloudAccountId))
	}

	if resourceType, ok := ctx.Value(constant.ResourceType).(string); ok {
		fields = append(fields, zap.String(string(constant.ResourceType), resourceType))
	}

	if startTime, ok := ctx.Value(constant.StartTime).(string); ok {
		fields = append(fields, zap.String(string(constant.StartTime), startTime))
	}

	if endTime, ok := ctx.Value(constant.EndTime).(string); ok {
		fields = append(fields, zap.String(string(constant.EndTime), endTime))
	}

	if duration, ok := ctx.Value(constant.Duration).(string); ok {
		fields = append(fields, zap.String(string(constant.Duration), duration))
	}

	return fields
}

func CtxLogger(ctx context.Context) *zap.Logger {
	if logger == nil {
		return zap.NewNop()
	}
	return logger.With(fieldsFromContext(ctx)...)
}

func GetCloudAccountId(ctx context.Context) string {
	if cloudAccountId, ok := ctx.Value(constant.CloudAccountId).(string); ok {
		return cloudAccountId
	}
	return ""
}
