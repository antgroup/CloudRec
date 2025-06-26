package schema

const (
	collect = "collect"
)

type TaskResp struct {
	TaskType   string
	TaskParams []TaskParam
}

type TaskParam struct {
	TaskId         int64
	CloudAccountId string
}

func queryTaskIds(params []TaskParam) []int64 {
	taskIds := make([]int64, 0)
	for _, param := range params {
		taskIds = append(taskIds, param.TaskId)
	}
	return taskIds
}

func matchTaskId(accounts []CloudAccount, task TaskResp) []CloudAccount {
	for i := range accounts {
		for _, t := range task.TaskParams {
			if accounts[i].CloudAccountId == t.CloudAccountId {
				accounts[i].TaskId = t.TaskId
				break
			}
		}
	}
	return accounts
}
