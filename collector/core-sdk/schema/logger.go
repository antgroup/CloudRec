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

package schema

import (
	"bytes"
	"container/ring"
	"encoding/json"
	"errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RemoteLogHook Is a custom zapcore.Core that sends logs to a remote service and deduplicates error logs
type RemoteLogHook struct {
	url       string
	client    *http.Client
	mu        sync.Mutex
	errorRing *ring.Ring // 使用环形缓冲区存储错误日志
	ringSize  int        // 环形缓冲区大小
}

func NewRemoteLogHook(url string) *RemoteLogHook {
	const defaultRingSize = 1000 // 默认存储最近1000条错误日志
	return &RemoteLogHook{
		url:       url,
		client:    &http.Client{Timeout: 5 * time.Second},
		errorRing: ring.New(defaultRingSize),
		ringSize:  defaultRingSize,
	}
}

// Enabled Implement the zapcore.Core interface to decide whether to log
func (remoteLogHook *RemoteLogHook) Enabled(level zapcore.Level) bool {
	return level >= zapcore.ErrorLevel
}

// With Implement the zapcore.Core interface and add structured fields
func (remoteLogHook *RemoteLogHook) With(fields []zapcore.Field) zapcore.Core {
	return remoteLogHook
}

// Check Implement the zapcore.Core interface and inspect log entries
func (remoteLogHook *RemoteLogHook) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if remoteLogHook.Enabled(entry.Level) {
		return checkedEntry.AddCore(entry, remoteLogHook)
	}
	return checkedEntry
}

// Write Implement the zapcore.Core interface to send logs to a remote service and perform deduplication
func (remoteLogHook *RemoteLogHook) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// Convert log entries and fields to JSON
	logData := map[string]interface{}{
		"level":   entry.Level.String(),
		"time":    entry.Time.Format(time.RFC3339),
		"message": entry.Message,
	}

	// Extract fields and store log data
	for _, field := range fields {
		logData[field.Key] = field.String
		if field.Integer != 0 {
			logData[field.Key] = strconv.FormatInt(field.Integer, 10)
		}
	}

	jsonData, err := json.Marshal(logData)
	if err != nil {
		return err
	}

	resp, err := remoteLogHook.client.Post(remoteLogHook.url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to send log: " + resp.Status)
	}

	return nil
}

// Sync Implement the zapcore.Core interface and flush the buffer
func (remoteLogHook *RemoteLogHook) Sync() error {
	return nil
}

// Clear the error log deduplication ring buffer
func (remoteLogHook *RemoteLogHook) Clear() {
	remoteLogHook.mu.Lock()
	defer remoteLogHook.mu.Unlock()
	remoteLogHook.errorRing = ring.New(remoteLogHook.ringSize)
}

type CloudRecLogger struct {
	remoteLogHook       *RemoteLogHook
	logger              *zap.Logger
	attentionErrorTexts []string
}

func InitCloudRecLogger(url string, attentionErrorCodes []string) *CloudRecLogger {
	hook := NewRemoteLogHook(url + "/api/agent/log-endpoint")

	consoleCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&bytes.Buffer{}),
		zap.DebugLevel,
	)

	core := zapcore.NewTee(
		consoleCore,
		hook,
	)

	logger := zap.New(core)
	return &CloudRecLogger{
		remoteLogHook:       hook,
		logger:              logger,
		attentionErrorTexts: attentionErrorCodes,
	}
}
func generateUniqueKey(fields ...string) string {
	return strings.Join(fields, "|")
}

func (cloudRecLogger *CloudRecLogger) matchAttentionError(err error) (bool, string) {
	msg := err.Error()

	if len(cloudRecLogger.attentionErrorTexts) <= 30 {
		for _, code := range cloudRecLogger.attentionErrorTexts {
			if strings.Contains(msg, code) {
				return true, code
			}
		}
		return false, ""
	} else {
		return cloudRecLogger.matchAttentionErrorParallel(err)
	}

}

func (cloudRecLogger *CloudRecLogger) matchAttentionErrorParallel(err error) (bool, string) {
	msg := err.Error()

	numWorkers := 4
	chunkSize := (len(cloudRecLogger.attentionErrorTexts) + numWorkers - 1) / numWorkers
	results := make(chan string, numWorkers)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(cloudRecLogger.attentionErrorTexts) {
			end = len(cloudRecLogger.attentionErrorTexts)
		}

		wg.Add(1)
		go func(subTexts []string) {
			defer wg.Done()
			for _, code := range subTexts {
				if strings.Contains(msg, code) {
					results <- code
					return
				}
			}
		}(cloudRecLogger.attentionErrorTexts[start:end])
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r != "" {
			return true, r
		}
	}

	return false, ""
}

const (
	ACCOUNT string = "ACCOUNT"
	SYSTEM  string = "SYSTEM"
)

func (cloudRecLogger *CloudRecLogger) logAccountError(platform, resourceType, cloudAccountId string, collectRecordId int64, err error) {
	match, description := cloudRecLogger.matchAttentionError(err)
	if !match {
		return
	}

	// generate unique key
	collectRecordIdStr := strconv.FormatInt(collectRecordId, 10)
	var uniqueKey = generateUniqueKey(ACCOUNT, platform, resourceType, cloudAccountId, description, collectRecordIdStr)

	// De-duplicate log messages using ring buffer
	cloudRecLogger.remoteLogHook.mu.Lock()
	defer cloudRecLogger.remoteLogHook.mu.Unlock()

	// Check whether it already exists in the circular buffer
	current := cloudRecLogger.remoteLogHook.errorRing
	for i := 0; i < cloudRecLogger.remoteLogHook.ringSize; i++ {
		if current.Value != nil {
			if msg, ok := current.Value.(string); ok && msg == uniqueKey {
				return
			}
		}
		current = current.Next()
	}

	// save to ring buffer
	cloudRecLogger.remoteLogHook.errorRing.Value = uniqueKey
	cloudRecLogger.remoteLogHook.errorRing = cloudRecLogger.remoteLogHook.errorRing.Next()

	// send to remote log service
	cloudRecLogger.logger.Error(err.Error(), zap.String("platform", platform),
		zap.String("resourceType", resourceType),
		zap.String("cloudAccountId", cloudAccountId),
		zap.String("uniqueKey", uniqueKey),
		zap.String("description", description),
		zap.String("collectRecordId", collectRecordIdStr),
		zap.String("type", ACCOUNT))
}

func (cloudRecLogger *CloudRecLogger) logSystemError(err error) {
	var uniqueKey = generateUniqueKey(SYSTEM, err.Error())
	cloudRecLogger.logger.Error(err.Error(),
		zap.String("type", SYSTEM),
		zap.String("uniqueKey", uniqueKey),
		zap.String("description", err.Error()))
}
