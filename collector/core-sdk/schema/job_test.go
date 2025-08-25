package schema

import (
	"testing"
	"time"
)

// createMockExecutor creates a mock executor for testing
func createMockExecutor() *Executor {
	platform := &Platform{
		PlatformConfig: PlatformConfig{
			CloudAccountMaxConcurrent: 4,
			Name: "test-platform",
			DefaultRegions: []string{"test-region"},
		},
	}
	return &Executor{
		platform: platform,
	}
}

// TestAccountQueueAddPriorityAccounts tests the AddPriorityAccounts method
func TestAccountQueueAddPriorityAccounts(t *testing.T) {
	// Create a new account queue with max size 5
	mockExecutor := createMockExecutor()
	aq := NewAccountQueue(5, mockExecutor)

	// Create some test accounts
	regularAccounts := []CloudAccount{
		{CloudAccountId: "regular-1", Platform: "aws"},
		{CloudAccountId: "regular-2", Platform: "aws"},
		{CloudAccountId: "regular-3", Platform: "aws"},
	}

	priorityAccounts := []CloudAccount{
		{CloudAccountId: "priority-1", Platform: "aws"},
		{CloudAccountId: "priority-2", Platform: "aws"},
	}

	// Add regular accounts to the queue
	addedRegular := aq.AddAccounts(regularAccounts)
	if addedRegular != 3 {
		t.Errorf("Expected to add 3 regular accounts, but added %d", addedRegular)
	}

	// Verify queue size
	queued, _, _ := aq.GetQueueStatus()
	if queued != 3 {
		t.Errorf("Expected queue size to be 3, but got %d", queued)
	}

	// Add priority accounts to the queue
	addedPriority := aq.AddPriorityAccounts(priorityAccounts)
	if addedPriority != 2 {
		t.Errorf("Expected to add 2 priority accounts, but added %d", addedPriority)
	}

	// Verify queue size after adding priority accounts
	queued, _, _ = aq.GetQueueStatus()
	if queued != 5 {
		t.Errorf("Expected queue size to be 5, but got %d", queued)
	}

	// Process the first account and verify it's a priority account
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond) // Give a little time for processing to start

	// Check if the first processed account is a priority account
	processing := false
	aq.mu.Lock()
	processing = aq.processing["priority-1"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected priority-1 to be processing, but it's not")
	}

	// Process the next account and verify it's also a priority account
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	// Check if the second processed account is a priority account
	processing = false
	aq.mu.Lock()
	processing = aq.processing["priority-2"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected priority-2 to be processing, but it's not")
	}

	// Process the next account and verify it's a regular account
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	// Check if the third processed account is a regular account
	processing = false
	aq.mu.Lock()
	processing = aq.processing["regular-1"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected regular-1 to be processing, but it's not")
	}
}

// TestAccountQueueAddPriorityAccountsWhenFull tests the AddPriorityAccounts method when queue is full
func TestAccountQueueAddPriorityAccountsWhenFull(t *testing.T) {
	// Create a new account queue with max size 3
	mockExecutor := createMockExecutor()
	aq := NewAccountQueue(3, mockExecutor)

	// Create some test accounts to fill the queue
	regularAccounts := []CloudAccount{
		{CloudAccountId: "regular-1", Platform: "aws"},
		{CloudAccountId: "regular-2", Platform: "aws"},
		{CloudAccountId: "regular-3", Platform: "aws"},
	}

	// Create priority accounts to try to add to a full queue
	priorityAccounts := []CloudAccount{
		{CloudAccountId: "priority-1", Platform: "aws"},
		{CloudAccountId: "priority-2", Platform: "aws"},
	}

	// Fill the queue with regular accounts
	addedRegular := aq.AddAccounts(regularAccounts)
	if addedRegular != 3 {
		t.Errorf("Expected to add 3 regular accounts, but added %d", addedRegular)
	}

	// Verify queue is full
	queued, _, available := aq.GetQueueStatus()
	if queued != 3 {
		t.Errorf("Expected queue size to be 3, but got %d", queued)
	}
	if available != 0 {
		t.Errorf("Expected available slots to be 0, but got %d", available)
	}

	// Try to add priority accounts to the full queue
	addedPriority := aq.AddPriorityAccounts(priorityAccounts)
	if addedPriority != 0 {
		t.Errorf("Expected to add 0 priority accounts to full queue, but added %d", addedPriority)
	}

	// Start processing one account to free up a slot in the queue
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	// Manually simulate account processing completion to free up a slot
	aq.mu.Lock()
	delete(aq.processing, "regular-1") // Assume regular-1 was processed first
	aq.mu.Unlock()

	// Verify one slot is now available
	queued, _, available = aq.GetQueueStatus()
	if available != 1 {
		t.Errorf("Expected available slots to be 1, but got %d", available)
	}

	// Now try to add priority accounts again
	addedPriority = aq.AddPriorityAccounts(priorityAccounts)
	if addedPriority != 1 {
		t.Errorf("Expected to add 1 priority account, but added %d", addedPriority)
	}

	// Process the next account and verify it's a priority account
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	// Check if the processed account is a priority account
	processing := false
	aq.mu.Lock()
	processing = aq.processing["priority-1"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected priority-1 to be processing, but it's not")
	}
}

// TestAccountQueueAddPriorityAccountsDuplicates tests the AddPriorityAccounts method with duplicate accounts
func TestAccountQueueAddPriorityAccountsDuplicates(t *testing.T) {
	// Create a new account queue with max size 5
	mockExecutor := createMockExecutor()
	aq := NewAccountQueue(5, mockExecutor)

	// Create some test accounts
	regularAccounts := []CloudAccount{
		{CloudAccountId: "account-1", Platform: "aws"},
		{CloudAccountId: "account-2", Platform: "aws"},
	}

	// Add regular accounts to the queue
	addedRegular := aq.AddAccounts(regularAccounts)
	if addedRegular != 2 {
		t.Errorf("Expected to add 2 regular accounts, but added %d", addedRegular)
	}

	// Create priority accounts with one duplicate
	priorityAccounts := []CloudAccount{
		{CloudAccountId: "account-1", Platform: "aws"}, // Duplicate
		{CloudAccountId: "priority-1", Platform: "aws"},
		{CloudAccountId: "priority-2", Platform: "aws"},
	}

	// Try to add priority accounts including the duplicate
	addedPriority := aq.AddPriorityAccounts(priorityAccounts)
	if addedPriority != 2 {
		t.Errorf("Expected to add 2 priority accounts (excluding duplicate), but added %d", addedPriority)
	}

	// Verify queue size
	queued, _, _ := aq.GetQueueStatus()
	if queued != 4 {
		t.Errorf("Expected queue size to be 4, but got %d", queued)
	}

	// Process accounts and verify order
	// First should be priority-1
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	processing := false
	aq.mu.Lock()
	processing = aq.processing["priority-1"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected priority-1 to be processing, but it's not")
	}

	// Second should be priority-2
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	processing = false
	aq.mu.Lock()
	processing = aq.processing["priority-2"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected priority-2 to be processing, but it's not")
	}

	// Third should be account-1 (which was already in the queue)
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	processing = false
	aq.mu.Lock()
	processing = aq.processing["account-1"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected account-1 to be processing, but it's not")
	}

	// Fourth should be account-2
	aq.ProcessNext()
	time.Sleep(10 * time.Millisecond)

	processing = false
	aq.mu.Lock()
	processing = aq.processing["account-2"]
	aq.mu.Unlock()

	if !processing {
		t.Errorf("Expected account-2 to be processing, but it's not")
	}
}