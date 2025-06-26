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
	"sync"
	"time"

	"github.com/core-sdk/log"
	"github.com/robfig/cron/v3"
)

// JobStatus to keep track of job state
type JobStatus struct {
	running bool
	mu      sync.Mutex
}

// loadCloudAccounts Load the cloud account and decrypt it, and at the same time put the local test account into the result
func (e *Executor) loadCloudAccounts(taskIds []int64) []CloudAccount {
	cloudAccountList, err := e.platform.client.LoadAccountFromServer(e.registry.RegistryValue, taskIds)
	if err != nil {
		log.GetWLogger().Warn(fmt.Sprintf("Failed to get account from server: %v", err))
		return nil
	}
	cloudAccountList = decryptCredentialsInfo(cloudAccountList, e.registry.SecretKey)
	cloudAccountList = append(cloudAccountList, e.platform.DefaultCloudAccounts...)
	return cloudAccountList
}

func (e *Executor) listCollectorTask() (tasks []TaskResp, err error) {
	tasks, err = e.platform.client.ListCollectorTask(e.registry.RegistryValue)
	return
}

func (e *Executor) Start() (err error) {
	if e.registered {
		time.Sleep(4 * time.Second)
		e.SendSupportResourceType()
	}

	if !e.opts.RunOnlyOnce {
		// Create a new cron instance
		// Recover from panics
		c := cron.New(cron.WithChain(
			cron.Recover(cron.DefaultLogger),
		))

		jobStatus := &JobStatus{}

		// Regular inspection tasks
		go func() {
			for {
				time.Sleep(15 * time.Second)
				if !jobStatus.running {
					tasks, taskErr := e.listCollectorTask()
					if taskErr != nil {
						log.GetWLogger().Warn(fmt.Sprintf("Failed to get task from server: %v", taskErr))
					} else if len(tasks) > 0 {
						// find task and match task type
						for _, task := range tasks {
							currentTask := task
							loadAccountFunc := func() []CloudAccount {
								return matchTaskId(e.loadCloudAccounts(queryTaskIds(currentTask.TaskParams)), currentTask)
							}
							switch currentTask.TaskType {
							case collect:
								go e.runJob(jobStatus, loadAccountFunc)
								// TODO other task type
							}
						}
					}
				}
			}
		}()

		// Function to load accounts
		loadAccountFunc := func() []CloudAccount {
			accounts := e.loadCloudAccounts(nil)
			return accounts
		}

		// Add a task for regular collection
		_, err = c.AddFunc(e.opts.Cron, func() {
			e.runJob(jobStatus, loadAccountFunc)
		})
		if err != nil {
			log.GetWLogger().Info(fmt.Sprintf("Error adding job: %v", err))
			return
		}

		// Immediately trigger the job once on startup
		go e.runJob(jobStatus, loadAccountFunc)

		log.GetWLogger().Info(fmt.Sprintf("———————— RESOURCE COLLECT AGENT START SUCCESSFULLY ————————"))
		c.Start()

		select {}
	} else {
		accounts := e.loadCloudAccounts(nil)
		param := CollectorParam{
			registered:     e.registered,
			CloudRecLogger: e.cloudRecLogger,
			accounts:       accounts,
		}
		err = e.platform.CollectorV3(param)
		log.GetWLogger().Info(fmt.Sprintf("———————— RUN ONCE DONE ————————"))
		return err
	}
}

// runJob executes the job, ensuring only one instance runs at a time
func (e *Executor) runJob(status *JobStatus, loadAccountFunc func() []CloudAccount) {
	status.mu.Lock()
	if status.running {
		status.mu.Unlock()
		log.GetWLogger().Warn("Previous job is still running, skipping this execution.")
		return
	}
	status.running = true
	status.mu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			log.GetWLogger().Error(fmt.Sprintf("Job panicked: %v", r))
		}
		status.mu.Lock()
		status.running = false
		status.mu.Unlock()
		jobCompleted()
	}()

	param := CollectorParam{
		registered:     e.registered,
		CloudRecLogger: e.cloudRecLogger,
		accounts:       loadAccountFunc(),
	}
	err := e.platform.CollectorV3(param)
	log.GetWLogger().Info(fmt.Sprintf("run job completed, err: %v", err))
}

// todo
// jobCompleted sends a notification that the job is done
func jobCompleted() {
	//log.GetWLogger().Info("Job has completed and notification has been sent.")
	// Notify via any desired method (e.g., channels, email, etc.)
	// Here, we'll just log for simplicity\n	logger.Println("Job has completed and notification has been sent.")\n}\n```
}
