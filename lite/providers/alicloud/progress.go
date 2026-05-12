package alicloud

import (
	"fmt"
	"strings"
)

func resourceRegionTask(resourceType string, region string) string {
	resourceType = strings.TrimSpace(resourceType)
	region = strings.TrimSpace(region)
	switch {
	case resourceType != "" && region != "":
		return fmt.Sprintf("%s@%s", resourceType, region)
	case resourceType != "":
		return resourceType
	case region != "":
		return region
	default:
		return "resource"
	}
}
