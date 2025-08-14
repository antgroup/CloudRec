package schema

import (
	"fmt"
	"github.com/core-sdk/log"
	"sync"
)

// TaskQueue manages task execution queue
type TaskQueue struct {
	tasks   chan func()
	workers int
	mu      sync.Mutex
	running bool
}

// NewTaskQueue creates a new task queue with specified number of workers
func NewTaskQueue(workers int) *TaskQueue {
	return &TaskQueue{
		tasks:   make(chan func(), 100), // buffered channel for 100 tasks
		workers: workers,
	}
}

// Start starts the task queue workers
func (tq *TaskQueue) Start() {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if tq.running {
		return
	}
	tq.running = true

	for i := 0; i < tq.workers; i++ {
		go tq.worker()
	}
}

// Stop stops the task queue
func (tq *TaskQueue) Stop() {
	tq.mu.Lock()
	defer tq.mu.Unlock()

	if !tq.running {
		return
	}
	tq.running = false
	close(tq.tasks)
}

// AddTask adds a task to the queue
func (tq *TaskQueue) AddTask(task func()) {
	tq.mu.Lock()
	running := tq.running
	tq.mu.Unlock()

	if !running {
		return
	}

	select {
	case tq.tasks <- task:
		// Task added successfully
	default:
		log.GetWLogger().Warn("Task queue is full, dropping task")
	}
}

// worker processes tasks from the queue
func (tq *TaskQueue) worker() {
	for task := range tq.tasks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.GetWLogger().Error(fmt.Sprintf("Task panicked: %v", r))
				}
			}()
			task()
		}()
	}
}

// AccountQueue manages cloud account processing queue
type AccountQueue struct {
	accounts   []CloudAccount
	maxSize    int
	mu         sync.RWMutex
	processing map[string]bool // track which accounts are being processed
	executor   *Executor
	taskQueue  *TaskQueue
}

// NewAccountQueue creates a new account queue with specified max size
func NewAccountQueue(maxSize int, executor *Executor) *AccountQueue {
	return &AccountQueue{
		accounts:   make([]CloudAccount, 0, maxSize),
		maxSize:    maxSize,
		processing: make(map[string]bool),
		executor:   executor,
		taskQueue:  NewTaskQueue(executor.platform.CloudAccountMaxConcurrent), // default 4 concurrent workers
	}
}

// Start starts the account queue processing
func (aq *AccountQueue) Start() {
	aq.taskQueue.Start()
}

// Stop stops the account queue processing
func (aq *AccountQueue) Stop() {
	aq.taskQueue.Stop()
}

// GetAvailableSlots returns the number of available slots in the queue
func (aq *AccountQueue) GetAvailableSlots() int {
	aq.mu.RLock()
	defer aq.mu.RUnlock()
	return aq.getAvailableSlotsLocked()
}

// getAvailableSlotsLocked returns available slots without acquiring lock (internal use)
func (aq *AccountQueue) getAvailableSlotsLocked() int {
	processingCount := len(aq.processing)
	queuedCount := len(aq.accounts)
	totalUsed := processingCount + queuedCount

	if totalUsed >= aq.maxSize {
		return 0
	}
	return aq.maxSize - totalUsed
}

// AddAccounts adds new accounts to the queue
func (aq *AccountQueue) AddAccounts(accounts []CloudAccount) int {
	aq.mu.Lock()
	defer aq.mu.Unlock()

	availableSlots := aq.getAvailableSlotsLocked()
	if availableSlots <= 0 {
		return 0
	}

	added := 0
	for _, account := range accounts {
		if added >= availableSlots {
			break
		}
		// Check if account is already in queue or being processed
		if !aq.isAccountInQueue(account.CloudAccountId) && !aq.processing[account.CloudAccountId] {
			aq.accounts = append(aq.accounts, account)
			added++
		}
	}

	return added
}

// AddPriorityAccounts adds high-priority accounts to the front of the queue
// These accounts will be processed before existing queued accounts
func (aq *AccountQueue) AddPriorityAccounts(accounts []CloudAccount) int {
	aq.mu.Lock()
	defer aq.mu.Unlock()

	availableSlots := aq.getAvailableSlotsLocked()
	if availableSlots <= 0 {
		return 0
	}

	added := 0
	priorityAccounts := make([]CloudAccount, 0, len(accounts))

	for _, account := range accounts {
		if added >= availableSlots {
			break
		}
		// Check if account is already in queue or being processed
		if !aq.isAccountInQueue(account.CloudAccountId) && !aq.processing[account.CloudAccountId] {
			priorityAccounts = append(priorityAccounts, account)
			added++
		}
	}

	if len(priorityAccounts) > 0 {
		// Insert priority accounts at the beginning of the queue
		aq.accounts = append(priorityAccounts, aq.accounts...)
	}

	return added
}

// ProcessNext processes the next account in the queue
func (aq *AccountQueue) ProcessNext() bool {
	aq.mu.Lock()
	if len(aq.accounts) == 0 {
		aq.mu.Unlock()
		return false
	}

	account := aq.accounts[0]
	aq.accounts = aq.accounts[1:]
	aq.processing[account.CloudAccountId] = true
	aq.mu.Unlock()

	// Add task to process this account
	aq.taskQueue.AddTask(func() {
		aq.processAccount(account)
	})

	return true
}

// processAccount processes a single cloud account
func (aq *AccountQueue) processAccount(account CloudAccount) {
	defer func() {
		aq.mu.Lock()
		delete(aq.processing, account.CloudAccountId)
		aq.mu.Unlock()

		// Try to process next account
		aq.ProcessNext()
	}()

	log.GetWLogger().Info(fmt.Sprintf("Processing cloud account: %s", account.CloudAccountId))

	param := CollectorParam{
		registered:     aq.executor.registered,
		CloudRecLogger: aq.executor.cloudRecLogger,
		accounts:       []CloudAccount{account},
	}

	err := aq.executor.platform.CollectorV3(param)
	if err != nil {
		log.GetWLogger().Error(fmt.Sprintf("Error processing account %s: %v", account.CloudAccountId, err))
	} else {
		log.GetWLogger().Info(fmt.Sprintf("Successfully processed account: %s", account.CloudAccountId))
	}
}

// isAccountInQueue checks if an account is already in the queue
func (aq *AccountQueue) isAccountInQueue(accountId string) bool {
	for _, account := range aq.accounts {
		if account.CloudAccountId == accountId {
			return true
		}
	}
	return false
}

// GetQueueStatus returns current queue status
func (aq *AccountQueue) GetQueueStatus() (queued int, processing int, available int) {
	aq.mu.RLock()
	defer aq.mu.RUnlock()

	return len(aq.accounts), len(aq.processing), aq.getAvailableSlotsLocked()
}
