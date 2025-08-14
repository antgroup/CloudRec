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
	"fmt"
	"github.com/core-sdk/log"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"time"
)

// GetSystemHealth Obtain system health status information
func GetSystemHealth() HealthStatus {
	var status HealthStatus

	// Get CPU usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		status.CPUUsage = fmt.Sprintf("%.1f%%", cpuPercent[0])
	} else {
		log.GetWLogger().Error("Failed to get CPU usage: " + err.Error())
		status.CPUUsage = "0%"
	}

	// Get memory usage
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		status.MemoryUsage = fmt.Sprintf("%.1f%%", memInfo.UsedPercent)
	} else {
		log.GetWLogger().Error("Failed to get memory usage: " + err.Error())
		status.MemoryUsage = "0%"
	}

	// Get root disk usage
	diskInfo, err := disk.Usage("/")
	if err == nil {
		status.DiskUsage = fmt.Sprintf("%.1f%%", diskInfo.UsedPercent)
	} else {
		log.GetWLogger().Error("Failed to get disk usage: " + err.Error())
		status.DiskUsage = "0%"
	}

	return status
}
