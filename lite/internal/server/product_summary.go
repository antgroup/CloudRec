package server

import (
	"fmt"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/model"
)

func productSummaryForAsset(asset model.Asset) map[string]any {
	product := productSummaryProduct(asset.ResourceType)
	switch product {
	case "OSS":
		return ossProductSummary(asset)
	case "SLS":
		return slsProductSummary(asset)
	case "ECS":
		return ecsProductSummary(asset)
	case "RAM":
		return ramProductSummary(asset)
	case "RDS", "Redis", "MongoDB", "PolarDB", "ClickHouse", "Lindorm", "HBase", "Elasticsearch", "Kafka", "RocketMQ":
		return dataProductSummary(asset, product)
	case "SLB", "ALB", "NLB":
		return loadBalancerProductSummary(asset, product)
	case "Security Group":
		return securityGroupProductSummary(asset)
	default:
		return genericProductSummary(asset)
	}
}

func productSummaryProduct(resourceType string) string {
	normalized := compactResourceType(resourceType)
	switch {
	case normalized == "oss" || strings.Contains(normalized, "bucket"):
		return "OSS"
	case normalized == "sls" || normalized == "logservice" || strings.Contains(normalized, "logstore") || strings.Contains(normalized, "logproject"):
		return "SLS"
	case normalized == "ramuser" || normalized == "ramrole" || strings.Contains(normalized, "ramuser") || strings.Contains(normalized, "ramrole"):
		return "RAM"
	case riskIsLoadBalancer(resourceType):
		if normalized == "alb" {
			return "ALB"
		}
		if normalized == "nlb" {
			return "NLB"
		}
		return "SLB"
	case normalized == "securitygroup" || strings.Contains(normalized, "securitygroup"):
		return "Security Group"
	case riskDataServiceForType(resourceType) != "":
		return riskDataServiceForType(resourceType)
	case normalized == "ecs" || normalized == "ecsinstance" || strings.HasPrefix(normalized, "ecs") || strings.Contains(normalized, "elasticcompute"):
		return "ECS"
	default:
		return ""
	}
}

func ossProductSummary(asset model.Asset) map[string]any {
	attributes := riskAssetAttributes(asset)
	bucket := firstRiskObject(
		riskMapValue(attributes, "BucketInfo", "bucketInfo"),
		riskMapValue(attributes, "Bucket", "bucket"),
		attributes,
	)
	acl := strings.ToLower(firstRiskString(
		riskMapValue(bucket, "ACL", "Acl", "acl"),
		riskMapValue(attributes, "ACL", "Acl", "acl"),
	))
	blockPublic := riskTruthy(firstRiskDefined(
		riskMapValue(bucket, "BlockPublicAccess", "blockPublicAccess"),
		riskMapValue(attributes, "BlockPublicAccess", "blockPublicAccess"),
	))
	policyStatus := firstRiskObject(
		riskMapValue(attributes, "BucketPolicyStatus", "bucketPolicyStatus"),
		riskMapValue(bucket, "BucketPolicyStatus", "bucketPolicyStatus"),
	)
	policyPublic, hasPolicyStatus := riskOptionalBool(riskMapValue(policyStatus, "IsPublic", "isPublic"))
	policyBody := firstRiskDefined(
		riskMapValue(attributes, "BucketPolicy", "bucketPolicy"),
		riskMapValue(bucket, "BucketPolicy", "bucketPolicy"),
		riskMapValue(attributes, "Policy", "policy"),
	)
	policy := riskPublicPolicySummary(policyBody, policyPublic, hasPolicyStatus, true)
	publicACL := acl == "public-read" || acl == "public-read-write"
	summary := baseProductSummary("OSS", asset)
	putSummary(summary, "acl", acl)
	putSummary(summary, "block_public_access", blockPublic)
	putSummary(summary, "public_acl", publicACL)
	putSummary(summary, "policy_public", policy.Public)
	putSummary(summary, "policy_write", policy.Write)
	putSummary(summary, "public_policy_statements", policy.StatementCount)
	putSummary(summary, "policy_principals", productPolicyPrincipals(policyBody))
	putSummary(summary, "effective_public", (publicACL || policy.Public) && !blockPublic)
	putSummary(summary, "versioning", firstRiskString(riskMapValue(firstRiskObject(riskMapValue(attributes, "VersioningConfig", "versioningConfig")), "Status", "status")))
	putSummary(summary, "referer_count", productListCount(riskMapValue(attributes, "RefererConfiguration", "RefererList", "refererList")))
	return summary
}

func slsProductSummary(asset model.Asset) map[string]any {
	attributes := riskAssetAttributes(asset)
	policyBody := firstRiskDefined(
		riskMapValue(attributes, "Policy", "policy"),
		riskMapValue(attributes, "ProjectPolicy", "projectPolicy"),
		riskMapValue(firstRiskObject(riskMapValue(attributes, "PolicyStatus", "policyStatus")), "body", "Body"),
	)
	policy := riskPublicPolicySummary(policyBody, false, false, false)
	summary := baseProductSummary("SLS", asset)
	putSummary(summary, "project_policy_public", policy.Public)
	putSummary(summary, "project_policy_write", policy.Write)
	putSummary(summary, "public_policy_statements", policy.StatementCount)
	putSummary(summary, "policy_principals", productPolicyPrincipals(policyBody))
	putSummary(summary, "logstore_count", firstNonZeroInt(
		productListCount(riskMapValue(attributes, "LogStores", "logstores", "LogStoreList", "logStoreList")),
		productListCount(riskMapValue(attributes, "LogStore", "logstore")),
	))
	putSummary(summary, "alert_count", productListCount(riskMapValue(attributes, "Alerts", "alerts", "AlertList", "alertList")))
	return summary
}

func dataProductSummary(asset model.Asset, product string) map[string]any {
	attributes := riskAssetAttributes(asset)
	accessLists := riskCollectAccessListEntries(attributes)
	wideACL := false
	for _, entry := range accessLists {
		if riskAnySource(entry) {
			wideACL = true
			break
		}
	}
	summary := baseProductSummary(product, asset)
	putSummary(summary, "public_endpoint", riskHasPublicDataEndpoint(attributes))
	putSummary(summary, "wide_whitelist", wideACL)
	putSummary(summary, "whitelist_count", len(accessLists))
	putSummary(summary, "whitelist_preview", redactedAccessListEvidence(accessLists))
	putSummary(summary, "engine", firstRiskString(riskMapValue(attributes, "Engine", "engine", "DBInstanceType", "dbInstanceType")))
	putSummary(summary, "version", firstRiskString(riskMapValue(attributes, "EngineVersion", "engineVersion", "DBInstanceVersion", "dbInstanceVersion")))
	putSummary(summary, "network_type", firstRiskString(riskMapValue(attributes, "DBInstanceNetType", "dbInstanceNetType", "NetworkType", "networkType")))
	putSummary(summary, "status", firstRiskString(riskMapValue(attributes, "Status", "status", "DBInstanceStatus", "dbInstanceStatus")))
	return summary
}

func ecsProductSummary(asset model.Asset) map[string]any {
	attributes := riskAssetAttributes(asset)
	publicIPs := productPublicIPv4s(attributes)
	securityGroups := productSecurityGroupIDs(attributes)
	summary := baseProductSummary("ECS", asset)
	putSummary(summary, "public_ip_count", len(publicIPs))
	putSummary(summary, "public_ips", publicIPs)
	putSummary(summary, "security_group_count", len(securityGroups))
	putSummary(summary, "security_groups", compactStringList(securityGroups, 8))
	putSummary(summary, "instance_type", firstRiskString(riskMapValue(attributes, "InstanceType", "instanceType")))
	putSummary(summary, "image_id", firstRiskString(riskMapValue(attributes, "ImageId", "imageId")))
	putSummary(summary, "key_pair", firstRiskString(riskMapValue(attributes, "KeyPairName", "keyPairName")))
	putSummary(summary, "disk_count", productListCount(riskMapValue(attributes, "Disks", "disks", "DiskIds", "diskIds")))
	putSummary(summary, "status", firstRiskString(riskMapValue(attributes, "Status", "status")))
	return summary
}

func ramProductSummary(asset model.Asset) map[string]any {
	attributes := riskAssetAttributes(asset)
	activeKeys, inactiveKeys, _ := riskAccessKeyCounts(attributes)
	if riskTruthy(riskMapValue(attributes, "ExistActiveAccessKey", "existActiveAccessKey")) && activeKeys == 0 {
		activeKeys = 1
	}
	policies := riskPolicySummaries(attributes)
	services := riskPolicyDataServices(policies)
	policyDocCount := riskPolicyDocumentCount(policies)
	sourceRestricted := riskPoliciesHaveSourceGuard(policies)
	sourceACLStatus := "unrestricted"
	if sourceRestricted {
		sourceACLStatus = "restricted"
	} else if policyDocCount == 0 {
		sourceACLStatus = "not_collected"
	}
	summary := baseProductSummary("RAM", asset)
	putSummary(summary, "active_ak_count", activeKeys)
	putSummary(summary, "inactive_ak_count", inactiveKeys)
	putSummary(summary, "policy_count", len(policies))
	putSummary(summary, "policy_document_count", policyDocCount)
	putSummary(summary, "source_acl_status", sourceACLStatus)
	putSummary(summary, "source_conditions", riskPolicySourceConditions(policies))
	putSummary(summary, "high_risk_services", productRiskPolicyServices(services))
	return summary
}

func loadBalancerProductSummary(asset model.Asset, product string) map[string]any {
	attributes := riskAssetAttributes(asset)
	loadBalancer := firstRiskObject(
		riskMapValue(attributes, "LoadBalancerAttribute", "loadBalancerAttribute"),
		riskMapValue(attributes, "LoadBalancer", "loadBalancer"),
		attributes,
	)
	listeners := riskTrafficListeners(attributes)
	backends := riskTrafficBackendRefs(attributes)
	addressType := firstRiskString(riskMapValue(loadBalancer, "AddressType", "addressType"))
	summary := baseProductSummary(product, asset)
	putSummary(summary, "address_type", addressType)
	putSummary(summary, "public_entry", riskIsPublicAddressType(addressType) || riskHasPublicAddress(loadBalancer))
	putSummary(summary, "address", firstNonEmptyRisk(firstRiskString(riskMapValue(loadBalancer, "Address", "address", "DNSName", "dnsName")), riskFirstAddress(loadBalancer)))
	putSummary(summary, "listener_count", len(listeners))
	putSummary(summary, "acl_off_listeners", productACLDisabledListeners(listeners))
	putSummary(summary, "backend_count", len(backends))
	return summary
}

func securityGroupProductSummary(asset model.Asset) map[string]any {
	group := riskTrafficSecurityGroupSummary(asset, asset.ResourceID)
	summary := baseProductSummary("Security Group", asset)
	putSummary(summary, "rule_count", len(group.Policies))
	putSummary(summary, "wide_open_ingress_count", len(group.OpenPolicies))
	putSummary(summary, "wide_open_ingress", group.OpenPolicies)
	return summary
}

func genericProductSummary(asset model.Asset) map[string]any {
	summary := baseProductSummary(firstNonEmptyRisk(asset.ResourceType, "Unknown"), asset)
	attributes := riskAssetAttributes(asset)
	putSummary(summary, "collected_fields", len(attributes))
	return summary
}

func baseProductSummary(product string, asset model.Asset) map[string]any {
	summary := map[string]any{
		"product":       product,
		"resource_type": asset.ResourceType,
	}
	if asset.Region != "" {
		summary["region"] = asset.Region
	}
	return summary
}

func putSummary(summary map[string]any, key string, value any) {
	switch typed := value.(type) {
	case nil:
		return
	case string:
		if strings.TrimSpace(typed) == "" {
			return
		}
	case []string:
		if len(typed) == 0 {
			return
		}
	case []trafficSGPolicy:
		if len(typed) == 0 {
			return
		}
	case []riskSourceCondition:
		if len(typed) == 0 {
			return
		}
	case []map[string]any:
		if len(typed) == 0 {
			return
		}
	case int:
		if typed == 0 {
			return
		}
	}
	summary[key] = value
}

func productPolicyPrincipals(policyBody any) []string {
	principals := make([]string, 0)
	for _, statement := range riskPolicyStatements(policyBody) {
		principals = append(principals, flattenRiskStrings(riskMapValue(statement, "Principal", "principal"))...)
	}
	return compactStringList(principals, 8)
}

func productRiskPolicyServices(services []riskPolicyService) []map[string]any {
	rows := make([]map[string]any, 0)
	for _, service := range services {
		if riskServiceRank(service.Level) < riskServiceRank("manage access") && service.PathKind != "data-plane access" {
			continue
		}
		rows = append(rows, map[string]any{
			"service":   service.Name,
			"level":     service.Level,
			"path_kind": service.PathKind,
		})
		if len(rows) >= 8 {
			break
		}
	}
	return rows
}

func productPublicIPv4s(value any) []string {
	addresses := make([]string, 0)
	riskWalkObjects(value, func(node map[string]any) {
		for key, raw := range node {
			key = strings.ToLower(key)
			if !strings.Contains(key, "ip") && !strings.Contains(key, "eip") && !strings.Contains(key, "address") {
				continue
			}
			for _, candidate := range flattenRiskStrings(raw) {
				if riskIsPublicIPv4(candidate) {
					addresses = append(addresses, candidate)
				}
			}
		}
	})
	return compactStringList(addresses, 8)
}

func productSecurityGroupIDs(value any) []string {
	ids := make([]string, 0)
	riskWalkObjects(value, func(node map[string]any) {
		for key, raw := range node {
			key = strings.ToLower(key)
			if !strings.Contains(key, "securitygroup") {
				continue
			}
			for _, candidate := range flattenRiskStrings(raw) {
				if riskLooksLikeSecurityGroupID(candidate) {
					ids = append(ids, nativeRiskID(candidate))
				}
			}
		}
	})
	return uniqueStrings(ids)
}

func productListCount(value any) int {
	items := riskNormalizeList(value)
	if len(items) == 1 {
		if text := strings.TrimSpace(fmt.Sprint(items[0])); text == "" || text == "<nil>" {
			return 0
		}
	}
	return len(items)
}

func productACLDisabledListeners(listeners []trafficListener) int {
	count := 0
	for _, listener := range listeners {
		if listener.ACLOff {
			count++
		}
	}
	return count
}

func firstNonZeroInt(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
