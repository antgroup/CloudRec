package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

const (
	riskPathAnonymousPublicDataAccess      = "anonymous_public_data_access"
	riskPathCredentialDataAccess           = "credential_data_access"
	riskPathCredentialControlPlaneExposure = "credential_control_plane_exposure"
	riskPathPublicTrafficExposure          = "public_traffic_exposure"
	riskPathDirectNetworkExposure          = "direct_network_exposure"
	riskPathBroadNetworkACL                = "broad_network_acl"
)

type riskPathFilter struct {
	AccountID    string
	Provider     string
	Region       string
	ResourceType string
	Service      string
	PathType     string
	Port         string
	OpenPolicy   string
	Q            string
	Limit        int
	Offset       int
}

type riskPathsResponse struct {
	Summary      riskPathSummary   `json:"summary"`
	Paths        []riskPathView    `json:"paths"`
	Groups       []riskPathGroup   `json:"groups,omitempty"`
	TrafficPaths []trafficPathView `json:"traffic_paths,omitempty"`
	Count        int               `json:"count"`
	Total        int               `json:"total"`
	TrafficCount int               `json:"traffic_count,omitempty"`
	TrafficTotal int               `json:"traffic_total,omitempty"`
	GroupsTotal  int               `json:"groups_total,omitempty"`
	Limit        int               `json:"limit,omitempty"`
	Offset       int               `json:"offset,omitempty"`
}

type riskPathSummary struct {
	Total                          int            `json:"total"`
	AnonymousPublicDataAccess      int            `json:"anonymous_public_data_access"`
	CredentialDataAccess           int            `json:"credential_data_access"`
	CredentialControlPlaneExposure int            `json:"credential_control_plane_exposure"`
	PublicTrafficExposure          int            `json:"public_traffic_exposure"`
	DirectNetworkExposure          int            `json:"direct_network_exposure"`
	BroadNetworkACL                int            `json:"broad_network_acl"`
	ServiceCounts                  map[string]int `json:"service_counts"`
	SeverityCounts                 map[string]int `json:"severity_counts"`
}

type riskPathView struct {
	ID        string              `json:"id"`
	PathType  string              `json:"path_type"`
	Severity  string              `json:"severity"`
	Service   string              `json:"service"`
	AccountID string              `json:"account_id,omitempty"`
	Provider  string              `json:"provider,omitempty"`
	Region    string              `json:"region,omitempty"`
	Source    *model.AssetSummary `json:"source,omitempty"`
	Target    model.AssetSummary  `json:"target"`
	Signals   []string            `json:"signals,omitempty"`
	Evidence  map[string]any      `json:"evidence,omitempty"`
}

type trafficPathView struct {
	ID                  string             `json:"id"`
	PathType            string             `json:"path_type"`
	Severity            string             `json:"severity"`
	AccountID           string             `json:"account_id,omitempty"`
	Provider            string             `json:"provider,omitempty"`
	Region              string             `json:"region,omitempty"`
	Entry               model.AssetSummary `json:"entry"`
	Address             string             `json:"address,omitempty"`
	AddressType         string             `json:"address_type,omitempty"`
	Listeners           []trafficListener  `json:"listeners,omitempty"`
	CloudFirewall       []trafficFWPolicy  `json:"cloud_firewall_policies,omitempty"`
	Backends            []trafficBackend   `json:"backends,omitempty"`
	OpenPolicyCount     int                `json:"open_policy_count"`
	CloudFWAllowCount   int                `json:"cloud_firewall_allow_count,omitempty"`
	CloudFWDropCount    int                `json:"cloud_firewall_drop_count,omitempty"`
	MissingBackendCount int                `json:"missing_backend_count,omitempty"`
	MissingSGCount      int                `json:"missing_security_group_count,omitempty"`
	Signals             []string           `json:"signals,omitempty"`
	Evidence            map[string]any     `json:"evidence,omitempty"`
}

type trafficListener struct {
	Port      string `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Status    string `json:"status,omitempty"`
	ACLStatus string `json:"acl_status,omitempty"`
	ACLType   string `json:"acl_type,omitempty"`
	ACLOff    bool   `json:"acl_off,omitempty"`
}

type trafficFWPolicy struct {
	Asset       *model.AssetSummary `json:"asset,omitempty"`
	ResourceID  string              `json:"resource_id,omitempty"`
	NativeID    string              `json:"native_id,omitempty"`
	Direction   string              `json:"direction,omitempty"`
	Action      string              `json:"action,omitempty"`
	Source      string              `json:"source,omitempty"`
	Destination string              `json:"destination,omitempty"`
	Protocol    string              `json:"protocol,omitempty"`
	Port        string              `json:"port,omitempty"`
	Order       string              `json:"order,omitempty"`
	Description string              `json:"description,omitempty"`
	Open        bool                `json:"open,omitempty"`
	Drop        bool                `json:"drop,omitempty"`
}

type trafficBackend struct {
	Asset          *model.AssetSummary    `json:"asset,omitempty"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	NativeID       string                 `json:"native_id,omitempty"`
	Name           string                 `json:"name,omitempty"`
	Port           string                 `json:"port,omitempty"`
	Weight         string                 `json:"weight,omitempty"`
	Status         string                 `json:"status,omitempty"`
	SecurityGroups []trafficSecurityGroup `json:"security_groups,omitempty"`
}

type trafficSecurityGroup struct {
	Asset        *model.AssetSummary `json:"asset,omitempty"`
	ResourceID   string              `json:"resource_id,omitempty"`
	NativeID     string              `json:"native_id,omitempty"`
	Name         string              `json:"name,omitempty"`
	Policies     []trafficSGPolicy   `json:"policies,omitempty"`
	OpenPolicies []trafficSGPolicy   `json:"open_policies,omitempty"`
}

type trafficSGPolicy struct {
	ID          string `json:"id,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Action      string `json:"action,omitempty"`
	Source      string `json:"source,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Port        string `json:"port,omitempty"`
	Priority    string `json:"priority,omitempty"`
	Description string `json:"description,omitempty"`
	Open        bool   `json:"open,omitempty"`
}

type riskPathGroup struct {
	ID          string               `json:"id"`
	PathType    string               `json:"path_type"`
	Severity    string               `json:"severity"`
	Service     string               `json:"service"`
	AccountID   string               `json:"account_id,omitempty"`
	Provider    string               `json:"provider,omitempty"`
	Region      string               `json:"region,omitempty"`
	Source      *model.AssetSummary  `json:"source,omitempty"`
	Targets     []model.AssetSummary `json:"targets,omitempty"`
	TargetCount int                  `json:"target_count"`
	Signals     []string             `json:"signals,omitempty"`
	Evidence    map[string]any       `json:"evidence,omitempty"`
}

type riskPolicySummary struct {
	Name             string
	Statements       []map[string]any
	SourceGuard      bool
	SourceConditions []riskSourceCondition
}

type riskPolicyService struct {
	Name             string
	Level            string
	PathKind         string
	SourceRestricted bool
	ResourcePatterns []string
	PolicyNames      []string
}

type riskIdentitySummary struct {
	Asset            model.Asset
	ActiveKeyCount   int
	InactiveKeyCount int
	ActiveKeyIDs     []string
	Policies         []riskPolicySummary
	Services         []riskPolicyService
	SourceConditions []riskSourceCondition
	SourceGuards     []riskPolicySourceGuard
	PolicyDocCount   int
}

type riskPolicySourceGuard struct {
	Service          string
	ResourcePatterns []string
	Conditions       []riskSourceCondition
}

type riskSourceCondition struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
}

func (h *handler) riskPaths(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseRiskPathFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, err := h.store.ListAssets(r.Context(), storage.AssetFilter{
		AccountID: filter.AccountID,
		Provider:  filter.Provider,
		Limit:     maxListLimit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list risk path assets failed")
		return
	}
	if assets == nil {
		assets = []model.Asset{}
	}
	relationships, err := h.store.ListAssetRelationships(r.Context(), storage.RelationshipFilter{
		AccountID: filter.AccountID,
		Provider:  filter.Provider,
		Limit:     maxListLimit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list risk path relationships failed")
		return
	}
	if relationships == nil {
		relationships = []model.AssetRelationship{}
	}
	writeJSON(w, http.StatusOK, buildRiskPathResponse(assets, relationships, filter))
}

func parseRiskPathFilter(r *http.Request) (riskPathFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), maxListLimit, maxListLimit)
	if err != nil {
		return riskPathFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return riskPathFilter{}, err
	}
	return riskPathFilter{
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     normalizeProvider(q.Get("provider")),
		Region:       strings.TrimSpace(q.Get("region")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		Service:      canonicalRiskService(q.Get("service")),
		PathType:     strings.TrimSpace(q.Get("path_type")),
		Port:         strings.TrimSpace(q.Get("port")),
		OpenPolicy:   strings.TrimSpace(q.Get("open_policy")),
		Q:            strings.TrimSpace(q.Get("q")),
		Limit:        limit,
		Offset:       offset,
	}, nil
}

func buildRiskPathResponse(assets []model.Asset, relationships []model.AssetRelationship, filter riskPathFilter) riskPathsResponse {
	paths := buildRiskPaths(assets)
	paths = filterRiskPaths(paths, filter)
	sortRiskPaths(paths)
	summary := summarizeRiskPaths(paths)
	trafficPaths := filterTrafficPaths(buildTrafficPaths(assets, relationships), filter)
	sortTrafficPaths(trafficPaths)
	summary.PublicTrafficExposure = len(trafficPaths)
	total := len(paths)
	groups := groupRiskPaths(paths)
	groupsTotal := len(groups)
	groups = paginateRiskPathGroups(groups, 0, filter.Limit)
	paths = paginateRiskPaths(paths, filter.Offset, filter.Limit)
	trafficTotal := len(trafficPaths)
	trafficPaths = paginateTrafficPaths(trafficPaths, filter.Offset, filter.Limit)
	return riskPathsResponse{
		Summary:      summary,
		Paths:        paths,
		Groups:       groups,
		TrafficPaths: trafficPaths,
		Count:        len(paths),
		Total:        total,
		TrafficCount: trafficTotal,
		TrafficTotal: trafficTotal,
		GroupsTotal:  groupsTotal,
		Limit:        filter.Limit,
		Offset:       filter.Offset,
	}
}

func buildRiskPaths(assets []model.Asset) []riskPathView {
	paths := make([]riskPathView, 0)
	targetsByService := map[string][]model.Asset{}

	for _, asset := range assets {
		service := riskDataServiceForType(asset.ResourceType)
		if service == "" {
			continue
		}
		targetsByService[service] = append(targetsByService[service], asset)
		paths = append(paths, directDataRiskPaths(asset, service)...)
	}

	for _, identity := range riskIdentitySummaries(assets) {
		if identity.ActiveKeyCount == 0 {
			continue
		}
		for _, service := range identity.Services {
			if service.SourceRestricted || !riskKnownDataService(service.Name) {
				continue
			}
			matched := 0
			for _, target := range targetsByService[service.Name] {
				if target.AccountID != "" && identity.Asset.AccountID != "" && target.AccountID != identity.Asset.AccountID {
					continue
				}
				if target.Provider != "" && identity.Asset.Provider != "" && target.Provider != identity.Asset.Provider {
					continue
				}
				if !riskResourceMatchesService(service, target) {
					continue
				}
				if riskSourceACLStatus(identity, service, target) == "restricted" {
					continue
				}
				paths = append(paths, credentialRiskPath(identity, service, target))
				matched++
				if matched >= 50 {
					break
				}
			}
		}
	}

	return dedupeRiskPaths(paths)
}

func buildTrafficPaths(assets []model.Asset, relationships []model.AssetRelationship) []trafficPathView {
	index := riskBuildAssetIndex(assets)
	securityGroupsByECS := riskGroupSecurityGroupsByECS(relationships, index)
	cloudFirewallPolicies := riskCloudFirewallInboundPolicies(assets)
	paths := make([]trafficPathView, 0)
	for _, asset := range assets {
		if !riskIsLoadBalancer(asset.ResourceType) {
			continue
		}
		path := riskTrafficPathFromLoadBalancer(asset, index, securityGroupsByECS, cloudFirewallPolicies)
		if path.ID == "" {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

type riskAssetIndex struct {
	byID       map[string]model.Asset
	byNativeID map[string][]model.Asset
}

func riskBuildAssetIndex(assets []model.Asset) riskAssetIndex {
	index := riskAssetIndex{
		byID:       map[string]model.Asset{},
		byNativeID: map[string][]model.Asset{},
	}
	for _, asset := range assets {
		for _, id := range []string{asset.ID, asset.ResourceID} {
			if strings.TrimSpace(id) != "" {
				index.byID[id] = asset
			}
		}
		for _, id := range riskAssetNativeIDs(asset) {
			key := strings.ToLower(id)
			index.byNativeID[key] = append(index.byNativeID[key], asset)
		}
	}
	return index
}

func riskAssetNativeIDs(asset model.Asset) []string {
	ids := []string{nativeRiskID(asset.ID), nativeRiskID(asset.ResourceID)}
	attributes := riskAssetAttributes(asset)
	resource := firstRiskObject(
		riskMapValue(attributes, "LoadBalancer", "LoadBalancerAttribute", "SecurityGroup", "Instance"),
		attributes,
	)
	for _, key := range []string{"LoadBalancerId", "SecurityGroupId", "InstanceId"} {
		if value := firstRiskString(riskMapValue(resource, key)); value != "" {
			ids = append(ids, value)
		}
	}
	return uniqueStrings(ids)
}

func riskGroupSecurityGroupsByECS(relationships []model.AssetRelationship, index riskAssetIndex) map[string][]trafficSecurityGroup {
	grouped := map[string][]trafficSecurityGroup{}
	for _, relationship := range relationships {
		if !riskLooksLikeSecurityGroupID(relationship.TargetResourceID) {
			continue
		}
		ecsAsset, _ := riskResolveAsset(index, relationship.SourceResourceID, "ECS", "")
		groupAsset, _ := riskResolveAsset(index, relationship.TargetResourceID, "Security Group", "")
		group := riskTrafficSecurityGroupSummary(groupAsset, relationship.TargetResourceID)
		for _, id := range []string{
			relationship.SourceResourceID,
			nativeRiskID(relationship.SourceResourceID),
			ecsAsset.ResourceID,
			nativeRiskID(ecsAsset.ResourceID),
		} {
			key := strings.ToLower(strings.TrimSpace(id))
			if key == "" {
				continue
			}
			if !trafficGroupListHas(grouped[key], group.ResourceID) {
				grouped[key] = append(grouped[key], group)
			}
		}
	}
	return grouped
}

func riskCloudFirewallInboundPolicies(assets []model.Asset) []trafficFWPolicy {
	policies := make([]trafficFWPolicy, 0)
	for _, asset := range assets {
		if compactResourceType(asset.ResourceType) != "cloudfw" {
			continue
		}
		attributes := riskAssetAttributes(asset)
		rawPolicy := firstRiskObject(riskMapValue(attributes, "Policy", "policy"), attributes)
		if len(rawPolicy) == 0 {
			continue
		}
		direction := strings.ToLower(firstRiskString(riskMapValue(rawPolicy, "Direction", "direction")))
		if direction != "in" {
			continue
		}
		action := strings.ToLower(firstRiskString(riskMapValue(rawPolicy, "AclAction", "aclAction", "Action", "action")))
		source := firstNonEmptyRisk(
			firstRiskString(riskMapValue(rawPolicy, "Source", "source")),
			strings.Join(flattenRiskStrings(riskMapValue(rawPolicy, "SourceGroupCidrs", "sourceGroupCidrs")), ","),
		)
		destination := firstNonEmptyRisk(
			firstRiskString(riskMapValue(rawPolicy, "Destination", "destination")),
			strings.Join(flattenRiskStrings(riskMapValue(rawPolicy, "DestinationGroupCidrs", "destinationGroupCidrs")), ","),
		)
		resourceID := firstNonEmptyRisk(asset.ResourceID, firstRiskString(riskMapValue(rawPolicy, "AclUuid", "aclUuid")), asset.ID)
		var summary *model.AssetSummary
		if asset.ID != "" || asset.ResourceID != "" {
			item := riskAssetSummary(asset)
			summary = &item
		}
		policies = append(policies, trafficFWPolicy{
			Asset:       summary,
			ResourceID:  resourceID,
			NativeID:    nativeRiskID(resourceID),
			Direction:   direction,
			Action:      action,
			Source:      source,
			Destination: destination,
			Protocol:    strings.ToUpper(firstRiskString(riskMapValue(rawPolicy, "Proto", "proto", "Protocol", "protocol"))),
			Port:        firstRiskString(riskMapValue(rawPolicy, "DestPort", "destPort", "Port", "port")),
			Order:       firstRiskString(riskMapValue(rawPolicy, "Order", "order", "Priority", "priority")),
			Description: firstRiskString(riskMapValue(rawPolicy, "Description", "description")),
			Open:        (action == "accept" || action == "log") && riskCloudFirewallPublicSource(rawPolicy),
			Drop:        action == "drop",
		})
	}
	return policies
}

func riskMatchingCloudFirewallPolicies(entry model.Asset, address string, listeners []trafficListener, policies []trafficFWPolicy) []trafficFWPolicy {
	matched := make([]trafficFWPolicy, 0)
	for _, policy := range policies {
		if policy.Asset != nil {
			if policy.Asset.AccountID != "" && entry.AccountID != "" && policy.Asset.AccountID != entry.AccountID {
				continue
			}
			if policy.Asset.Provider != "" && entry.Provider != "" && policy.Asset.Provider != entry.Provider {
				continue
			}
		}
		if !riskCloudFirewallDestinationMatches(policy, address) {
			continue
		}
		if !riskCloudFirewallListenerMatches(policy, listeners) {
			continue
		}
		matched = append(matched, policy)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Order < matched[j].Order
	})
	return matched
}

func riskCloudFirewallPublicSource(policy map[string]any) bool {
	if riskAnySource(firstRiskString(riskMapValue(policy, "Source", "source"))) {
		return true
	}
	for _, source := range flattenRiskStrings(riskMapValue(policy, "SourceGroupCidrs", "sourceGroupCidrs")) {
		if riskAnySource(source) {
			return true
		}
	}
	return false
}

func riskCloudFirewallDestinationMatches(policy trafficFWPolicy, address string) bool {
	if riskAnySource(policy.Destination) {
		return true
	}
	if address != "" && strings.EqualFold(policy.Destination, address) {
		return true
	}
	for _, destination := range regexp.MustCompile(`[,\s;]+`).Split(policy.Destination, -1) {
		destination = strings.TrimSpace(destination)
		if destination == "" {
			continue
		}
		if riskAnySource(destination) || (address != "" && strings.EqualFold(destination, address)) {
			return true
		}
	}
	return false
}

func riskCloudFirewallListenerMatches(policy trafficFWPolicy, listeners []trafficListener) bool {
	if len(listeners) == 0 {
		return true
	}
	for _, listener := range listeners {
		if !riskCloudFirewallProtocolMatches(policy.Protocol, listener.Protocol) {
			continue
		}
		if riskPortValueMatches(policy.Port, listener.Port) {
			return true
		}
	}
	return false
}

func riskCloudFirewallProtocolMatches(policyProtocol string, listenerProtocol string) bool {
	policyProtocol = strings.ToUpper(strings.TrimSpace(policyProtocol))
	listenerProtocol = strings.ToUpper(strings.TrimSpace(listenerProtocol))
	return policyProtocol == "" || policyProtocol == "ANY" || listenerProtocol == "" || policyProtocol == listenerProtocol
}

func riskPortValueMatches(policyPort string, listenerPort string) bool {
	policyPort = strings.TrimSpace(policyPort)
	listenerPort = strings.TrimSpace(listenerPort)
	if policyPort == "" || strings.EqualFold(policyPort, "any") || policyPort == "*" {
		return true
	}
	return trafficPolicyMatchesPort(trafficSGPolicy{Port: policyPort}, listenerPort)
}

func riskTrafficPathFromLoadBalancer(asset model.Asset, index riskAssetIndex, securityGroupsByECS map[string][]trafficSecurityGroup, cloudFirewallPolicies []trafficFWPolicy) trafficPathView {
	attributes := riskAssetAttributes(asset)
	loadBalancer := firstRiskObject(
		riskMapValue(attributes, "LoadBalancerAttribute", "loadBalancerAttribute"),
		riskMapValue(attributes, "LoadBalancer", "loadBalancer"),
		attributes,
	)
	addressType := firstRiskString(riskMapValue(loadBalancer, "AddressType", "addressType"))
	isPublic := riskIsPublicAddressType(addressType) || riskHasPublicAddress(loadBalancer)
	if !isPublic {
		return trafficPathView{}
	}
	listeners := riskTrafficListeners(attributes)
	address := firstNonEmptyRisk(firstRiskString(riskMapValue(loadBalancer, "Address", "address", "DNSName", "dnsName")), riskFirstAddress(loadBalancer))
	cloudFirewall := riskMatchingCloudFirewallPolicies(asset, address, listeners, cloudFirewallPolicies)
	cloudFWAllow := 0
	cloudFWDrop := 0
	for _, policy := range cloudFirewall {
		if policy.Open {
			cloudFWAllow++
		}
		if policy.Drop {
			cloudFWDrop++
		}
	}
	backends := make([]trafficBackend, 0)
	missingSG := 0
	openPolicies := 0
	for _, backendRef := range riskTrafficBackendRefs(attributes) {
		ecsAsset, ok := riskResolveAsset(index, backendRef.ResourceID, "ECS", asset.Region)
		resourceID := backendRef.ResourceID
		if ok && ecsAsset.ResourceID != "" {
			resourceID = ecsAsset.ResourceID
		}
		groups := dedupeTrafficSecurityGroups(append(
			append([]trafficSecurityGroup{}, securityGroupsByECS[strings.ToLower(resourceID)]...),
			securityGroupsByECS[strings.ToLower(nativeRiskID(resourceID))]...,
		))
		if len(groups) == 0 {
			missingSG++
		}
		for _, group := range groups {
			openPolicies += len(group.OpenPolicies)
		}
		var assetSummary *model.AssetSummary
		if ok {
			summary := riskAssetSummary(ecsAsset)
			assetSummary = &summary
		}
		backends = append(backends, trafficBackend{
			Asset:          assetSummary,
			ResourceID:     resourceID,
			NativeID:       nativeRiskID(resourceID),
			Name:           firstNonEmptyRisk(ecsAsset.Name, backendRef.ResourceID),
			Port:           backendRef.Port,
			Weight:         backendRef.Weight,
			Status:         backendRef.Status,
			SecurityGroups: groups,
		})
	}
	severity := model.SeverityHigh
	signals := []string{"public_load_balancer"}
	if openPolicies > 0 {
		severity = model.SeverityCritical
		signals = append(signals, "wide_open_security_group")
	}
	if cloudFWAllow > 0 {
		severity = model.SeverityCritical
		signals = append(signals, "cloudfw_inbound_allow")
	}
	if cloudFWDrop > 0 {
		signals = append(signals, "cloudfw_inbound_drop")
	}
	if len(backends) == 0 {
		signals = append(signals, "backend_not_collected")
	}
	if missingSG > 0 {
		signals = append(signals, "security_group_not_collected")
	}
	path := trafficPathView{
		PathType:            riskPathPublicTrafficExposure,
		Severity:            severity,
		AccountID:           asset.AccountID,
		Provider:            asset.Provider,
		Region:              asset.Region,
		Entry:               riskAssetSummary(asset),
		Address:             address,
		AddressType:         addressType,
		Listeners:           listeners,
		CloudFirewall:       cloudFirewall,
		Backends:            backends,
		OpenPolicyCount:     openPolicies + cloudFWAllow,
		CloudFWAllowCount:   cloudFWAllow,
		CloudFWDropCount:    cloudFWDrop,
		MissingBackendCount: boolToInt(len(backends) == 0),
		MissingSGCount:      missingSG,
		Signals:             uniqueStrings(signals),
		Evidence: map[string]any{
			"listener_count":               len(listeners),
			"backend_count":                len(backends),
			"open_security_group_rules":    openPolicies,
			"cloudfw_inbound_allow_rules":  cloudFWAllow,
			"cloudfw_inbound_drop_rules":   cloudFWDrop,
			"missing_security_group_edges": missingSG,
		},
	}
	path.ID = sanitizeRiskPathID(strings.Join([]string{path.PathType, path.Entry.ResourceID}, ":"))
	return path
}

type trafficBackendRef struct {
	ResourceID string
	Port       string
	Weight     string
	Status     string
}

func riskTrafficBackendRefs(attributes map[string]any) []trafficBackendRef {
	refs := make([]trafficBackendRef, 0)
	seen := map[string]bool{}
	riskWalkObjects(attributes, func(node map[string]any) {
		serverID := firstRiskString(riskMapValue(node, "ServerId", "serverId", "InstanceId", "instanceId"))
		serverType := strings.ToLower(firstRiskString(riskMapValue(node, "ServerType", "serverType", "Type", "type")))
		if serverID == "" || (!riskLooksLikeECSID(serverID) && serverType != "ecs" && serverType != "eni") {
			return
		}
		ref := trafficBackendRef{
			ResourceID: serverID,
			Port:       firstRiskString(riskMapValue(node, "Port", "port", "BackendServerPort", "backendServerPort")),
			Weight:     firstRiskString(riskMapValue(node, "Weight", "weight")),
			Status:     firstRiskString(riskMapValue(node, "Status", "status")),
		}
		key := ref.ResourceID + ":" + ref.Port
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, ref)
	})
	return refs
}

func riskTrafficListeners(attributes map[string]any) []trafficListener {
	listeners := make([]trafficListener, 0)
	seen := map[string]bool{}
	addListener := func(listener map[string]any) {
		port := firstRiskString(riskMapValue(listener, "ListenerPort", "Port", "StartPort", "listenerPort", "port"))
		protocol := strings.ToUpper(firstRiskString(riskMapValue(listener, "ListenerProtocol", "Protocol", "listenerProtocol", "protocol")))
		if port == "" && protocol == "" {
			return
		}
		aclStatus := firstRiskString(riskMapValue(listener, "AclStatus", "aclStatus"))
		item := trafficListener{
			Port:      port,
			Protocol:  protocol,
			Status:    firstRiskString(riskMapValue(listener, "Status", "ListenerStatus", "status", "listenerStatus")),
			ACLStatus: aclStatus,
			ACLType:   firstRiskString(riskMapValue(listener, "AclType", "aclType")),
			ACLOff:    strings.EqualFold(aclStatus, "off"),
		}
		key := item.Protocol + ":" + item.Port
		if seen[key] {
			return
		}
		seen[key] = true
		listeners = append(listeners, item)
	}
	for _, raw := range riskNormalizeList(riskMapValue(attributes, "Listeners", "listeners")) {
		addListener(firstRiskObject(riskMapValue(riskObject(raw), "Listener", "ListenerAttribute", "listener"), raw))
	}
	riskWalkObjects(attributes, func(node map[string]any) {
		if riskMapValue(node, "ListenerPort", "listenerPort", "StartPort", "Port", "port") != nil {
			addListener(node)
		}
	})
	return listeners
}

func riskTrafficSecurityGroupSummary(asset model.Asset, fallbackID string) trafficSecurityGroup {
	attributes := riskAssetAttributes(asset)
	groupInfo := firstRiskObject(riskMapValue(attributes, "SecurityGroup", "securityGroup"), attributes)
	policies := make([]trafficSGPolicy, 0)
	for _, raw := range riskNormalizeList(riskMapValue(attributes, "Permissions", "permissions")) {
		policy := riskTrafficSGPolicy(riskObject(raw))
		if policy.Protocol != "" || policy.Source != "" || policy.Port != "" {
			policies = append(policies, policy)
		}
	}
	resourceID := firstNonEmptyRisk(asset.ResourceID, fallbackID)
	var summary *model.AssetSummary
	if asset.ID != "" || asset.ResourceID != "" {
		item := riskAssetSummary(asset)
		summary = &item
	}
	group := trafficSecurityGroup{
		Asset:      summary,
		ResourceID: resourceID,
		NativeID:   nativeRiskID(resourceID),
		Name:       firstNonEmptyRisk(asset.Name, firstRiskString(riskMapValue(groupInfo, "SecurityGroupName", "securityGroupName")), nativeRiskID(resourceID)),
		Policies:   policies,
	}
	for _, policy := range policies {
		if policy.Open {
			group.OpenPolicies = append(group.OpenPolicies, policy)
		}
	}
	return group
}

func riskTrafficSGPolicy(raw map[string]any) trafficSGPolicy {
	policy := firstRiskObject(riskMapValue(raw, "Permission", "permission"), raw)
	direction := strings.ToLower(firstRiskString(riskMapValue(policy, "Direction", "direction")))
	action := strings.ToLower(firstRiskString(riskMapValue(policy, "Policy", "policy")))
	source := firstNonEmptyRisk(
		firstRiskString(riskMapValue(policy, "SourceCidrIp", "sourceCidrIp")),
		firstRiskString(riskMapValue(policy, "Ipv6SourceCidrIp", "ipv6SourceCidrIp")),
		firstRiskString(riskMapValue(policy, "SourceGroupId", "sourceGroupId")),
	)
	result := trafficSGPolicy{
		ID:          firstRiskString(riskMapValue(policy, "SecurityGroupRuleId", "securityGroupRuleId")),
		Direction:   direction,
		Action:      action,
		Source:      source,
		Protocol:    strings.ToUpper(firstRiskString(riskMapValue(policy, "IpProtocol", "ipProtocol"))),
		Port:        firstRiskString(riskMapValue(policy, "PortRange", "portRange")),
		Priority:    firstRiskString(riskMapValue(policy, "Priority", "priority")),
		Description: firstRiskString(riskMapValue(policy, "Description", "description")),
	}
	result.Open = direction == "ingress" && action != "drop" && riskAnySource(source)
	return result
}

func riskResolveAsset(index riskAssetIndex, resourceID string, preferredType string, preferredRegion string) (model.Asset, bool) {
	if strings.TrimSpace(resourceID) == "" {
		return model.Asset{}, false
	}
	if asset, ok := index.byID[resourceID]; ok && riskAssetMatches(asset, preferredType, preferredRegion) {
		return asset, true
	}
	for _, asset := range index.byNativeID[strings.ToLower(nativeRiskID(resourceID))] {
		if riskAssetMatches(asset, preferredType, preferredRegion) {
			return asset, true
		}
	}
	return model.Asset{}, false
}

func riskAssetMatches(asset model.Asset, preferredType string, preferredRegion string) bool {
	if asset.ID == "" && asset.ResourceID == "" {
		return false
	}
	if preferredType != "" && !sameResourceType(asset.ResourceType, preferredType) {
		if compactResourceType(preferredType) == "securitygroup" && !riskLooksLikeSecurityGroupID(asset.ResourceID) {
			return false
		}
		if compactResourceType(preferredType) == "ecs" && !riskLooksLikeECSID(asset.ResourceID) {
			return false
		}
	}
	if preferredRegion != "" && asset.Region != "" && asset.Region != preferredRegion {
		return false
	}
	return true
}

func trafficGroupListHas(groups []trafficSecurityGroup, resourceID string) bool {
	for _, group := range groups {
		if group.ResourceID != "" && group.ResourceID == resourceID {
			return true
		}
		if group.NativeID != "" && group.NativeID == nativeRiskID(resourceID) {
			return true
		}
	}
	return false
}

func dedupeTrafficSecurityGroups(groups []trafficSecurityGroup) []trafficSecurityGroup {
	seen := map[string]bool{}
	result := make([]trafficSecurityGroup, 0, len(groups))
	for _, group := range groups {
		key := firstNonEmptyRisk(group.ResourceID, group.NativeID, group.Name)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, group)
	}
	return result
}

func riskIsLoadBalancer(resourceType string) bool {
	normalized := compactResourceType(resourceType)
	return normalized == "slb" || normalized == "alb" || normalized == "nlb" || strings.Contains(normalized, "loadbalancer")
}

func riskLooksLikeECSID(value string) bool {
	text := strings.ToLower(nativeRiskID(value))
	return strings.HasPrefix(text, "i-")
}

func riskLooksLikeSecurityGroupID(value string) bool {
	text := strings.ToLower(nativeRiskID(value))
	return strings.HasPrefix(text, "sg-") || strings.Contains(compactResourceType(value), "securitygroup")
}

func riskHasPublicAddress(value any) bool {
	found := false
	riskWalkObjects(value, func(node map[string]any) {
		if found {
			return
		}
		for key, raw := range node {
			keyLower := strings.ToLower(key)
			if strings.Contains(keyLower, "addresstype") || strings.Contains(keyLower, "networktype") {
				if riskIsPublicAddressType(firstRiskString(raw)) {
					found = true
					return
				}
			}
			if strings.Contains(keyLower, "address") || strings.Contains(keyLower, "ip") || strings.Contains(keyLower, "dns") {
				for _, candidate := range flattenRiskStrings(raw) {
					if riskIsPublicIPv4(candidate) || strings.Contains(strings.ToLower(candidate), "internet") || strings.Contains(strings.ToLower(candidate), "public") {
						found = true
						return
					}
				}
			}
		}
	})
	return found
}

func riskFirstAddress(value any) string {
	address := ""
	riskWalkObjects(value, func(node map[string]any) {
		if address != "" {
			return
		}
		for _, key := range []string{"Address", "address", "DNSName", "dnsName", "IpAddress", "ipAddress", "IPAddress"} {
			if candidate := firstRiskString(riskMapValue(node, key)); candidate != "" {
				address = candidate
				return
			}
		}
	})
	return address
}

func firstNonEmptyRisk(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func directDataRiskPaths(asset model.Asset, service string) []riskPathView {
	switch service {
	case "OSS":
		return ossDirectRiskPaths(asset)
	case "SLS":
		return slsDirectRiskPaths(asset)
	default:
		return databaseDirectRiskPaths(asset, service)
	}
}

func ossDirectRiskPaths(asset model.Asset) []riskPathView {
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
	publicACL := acl == "public-read" || acl == "public-read-write"

	policyStatus := firstRiskObject(
		riskMapValue(attributes, "BucketPolicyStatus", "bucketPolicyStatus"),
		riskMapValue(bucket, "BucketPolicyStatus", "bucketPolicyStatus"),
	)
	policyPublic, hasPolicyStatus := riskOptionalBool(riskMapValue(policyStatus, "IsPublic", "isPublic"))
	policy := riskPublicPolicySummary(firstRiskDefined(
		riskMapValue(attributes, "BucketPolicy", "bucketPolicy"),
		riskMapValue(bucket, "BucketPolicy", "bucketPolicy"),
		riskMapValue(attributes, "Policy", "policy"),
	), policyPublic, hasPolicyStatus, true)

	signals := make([]string, 0, 3)
	if publicACL && !blockPublic {
		if acl == "public-read-write" {
			signals = append(signals, "public_write_acl")
		} else {
			signals = append(signals, "public_read_acl")
		}
	}
	if policy.Public && !blockPublic {
		if policy.Write {
			signals = append(signals, "public_policy_write")
		} else {
			signals = append(signals, "public_policy")
		}
	}
	if len(signals) == 0 {
		return nil
	}
	severity := model.SeverityHigh
	if acl == "public-read-write" || policy.Write {
		severity = model.SeverityCritical
	}
	return []riskPathView{newRiskPath(riskPathAnonymousPublicDataAccess, severity, "OSS", nil, asset, signals, map[string]any{
		"acl":                 acl,
		"block_public_access": blockPublic,
		"policy_public":       policy.Public,
		"policy_write":        policy.Write,
	})}
}

func slsDirectRiskPaths(asset model.Asset) []riskPathView {
	attributes := riskAssetAttributes(asset)
	policyStatus := firstRiskObject(
		riskMapValue(attributes, "PolicyStatus", "policyStatus"),
		riskMapValue(attributes, "ProjectPolicy", "projectPolicy"),
	)
	body := firstRiskDefined(
		riskMapValue(policyStatus, "body", "Body"),
		riskMapValue(attributes, "Policy", "policy"),
	)
	policy := riskPublicPolicySummary(body, false, false, false)
	if !policy.Public {
		return nil
	}
	signals := []string{"public_project_policy"}
	if policy.Write {
		signals = append(signals, "public_policy_write")
	}
	severity := model.SeverityHigh
	if policy.Write {
		severity = model.SeverityCritical
	}
	return []riskPathView{newRiskPath(riskPathAnonymousPublicDataAccess, severity, "SLS", nil, asset, signals, map[string]any{
		"policy_public":     policy.Public,
		"policy_write":      policy.Write,
		"public_statements": policy.StatementCount,
	})}
}

func databaseDirectRiskPaths(asset model.Asset, service string) []riskPathView {
	attributes := riskAssetAttributes(asset)
	publicEndpoint := riskHasPublicDataEndpoint(attributes)
	accessLists := riskCollectAccessListEntries(attributes)
	wideACL := false
	for _, entry := range accessLists {
		if riskAnySource(entry) {
			wideACL = true
			break
		}
	}
	if !publicEndpoint && !wideACL {
		return nil
	}
	pathType := riskPathDirectNetworkExposure
	severity := model.SeverityHigh
	if publicEndpoint && wideACL {
		severity = model.SeverityCritical
	} else if wideACL && !publicEndpoint {
		pathType = riskPathBroadNetworkACL
		severity = model.SeverityMedium
	}
	signals := make([]string, 0, 2)
	if publicEndpoint {
		signals = append(signals, "public_endpoint")
	}
	if wideACL {
		signals = append(signals, "wide_whitelist")
	}
	return []riskPathView{newRiskPath(pathType, severity, service, nil, asset, signals, map[string]any{
		"public_endpoint": publicEndpoint,
		"wide_whitelist":  wideACL,
		"access_lists":    redactedAccessListEvidence(accessLists),
	})}
}

func credentialRiskPath(identity riskIdentitySummary, service riskPolicyService, target model.Asset) riskPathView {
	pathType := riskPathCredentialControlPlaneExposure
	sourceACLStatus := riskSourceACLStatus(identity, service, target)
	sourceSignal := "source_unrestricted"
	if sourceACLStatus == "not_collected" {
		sourceSignal = "source_acl_not_collected"
	}
	signals := []string{"active_ak", sourceSignal, service.PathKind}
	severity := model.SeverityHigh
	if service.Name == "OSS" || service.Name == "SLS" {
		pathType = riskPathCredentialDataAccess
		if service.Level == "full access" || service.Level == "manage access" {
			severity = model.SeverityCritical
		}
	} else if service.Level == "read access" {
		severity = model.SeverityMedium
	}
	return newRiskPath(pathType, severity, service.Name, &identity.Asset, target, signals, map[string]any{
		"active_key_count":           identity.ActiveKeyCount,
		"active_access_keys":         compactStringList(identity.ActiveKeyIDs, 8),
		"inactive_key_count":         identity.InactiveKeyCount,
		"policy_count":               len(identity.Policies),
		"policy_document_count":      identity.PolicyDocCount,
		"policy_documents_collected": identity.PolicyDocCount > 0,
		"policy_names":               service.PolicyNames,
		"permission_level":           service.Level,
		"path_kind":                  service.PathKind,
		"resource_patterns":          compactStringList(service.ResourcePatterns, 8),
		"source_acl_status":          sourceACLStatus,
		"source_restricted":          sourceACLStatus == "restricted",
		"source_conditions":          identity.SourceConditions,
		"source_guard_count":         len(identity.SourceGuards),
	})
}

func newRiskPath(pathType string, severity string, service string, source *model.Asset, target model.Asset, signals []string, evidence map[string]any) riskPathView {
	view := riskPathView{
		PathType:  pathType,
		Severity:  severity,
		Service:   service,
		AccountID: target.AccountID,
		Provider:  target.Provider,
		Region:    target.Region,
		Target:    riskAssetSummary(target),
		Signals:   uniqueStrings(signals),
		Evidence:  evidence,
	}
	if source != nil {
		summary := riskAssetSummary(*source)
		view.Source = &summary
		if view.AccountID == "" {
			view.AccountID = source.AccountID
		}
		if view.Provider == "" {
			view.Provider = source.Provider
		}
	}
	view.ID = riskPathID(view)
	return view
}

func riskAssetSummary(asset model.Asset) model.AssetSummary {
	return model.AssetSummary{
		ID:           asset.ID,
		AccountID:    asset.AccountID,
		Provider:     asset.Provider,
		ResourceType: asset.ResourceType,
		ResourceID:   asset.ResourceID,
		Region:       asset.Region,
		Name:         asset.Name,
	}
}

func riskIdentitySummaries(assets []model.Asset) []riskIdentitySummary {
	identities := make([]riskIdentitySummary, 0)
	for _, asset := range assets {
		if !riskIsRAMUser(asset.ResourceType) {
			continue
		}
		attributes := riskAssetAttributes(asset)
		activeKeys, inactiveKeys, activeKeyIDs := riskAccessKeyCounts(attributes)
		if riskTruthy(riskMapValue(attributes, "ExistActiveAccessKey", "existActiveAccessKey")) && activeKeys == 0 {
			activeKeys = 1
		}
		policies := riskPolicySummaries(attributes)
		sourceConditions := riskPolicySourceConditions(policies)
		identities = append(identities, riskIdentitySummary{
			Asset:            asset,
			ActiveKeyCount:   activeKeys,
			InactiveKeyCount: inactiveKeys,
			ActiveKeyIDs:     activeKeyIDs,
			Policies:         policies,
			Services:         riskPolicyDataServices(policies),
			SourceConditions: sourceConditions,
			SourceGuards:     riskPolicySourceGuards(policies),
			PolicyDocCount:   riskPolicyDocumentCount(policies),
		})
	}
	return identities
}

func riskAccessKeyCounts(attributes map[string]any) (int, int, []string) {
	active := 0
	inactive := 0
	activeIDs := []string{}
	keys := append(
		riskNormalizeList(riskMapValue(attributes, "AccessKeys", "accessKeys")),
		riskNormalizeList(riskMapValue(attributes, "AccessKey", "accessKey"))...,
	)
	for _, raw := range keys {
		key := firstRiskObject(riskMapValue(riskObject(raw), "AccessKey", "accessKey"), raw)
		status := strings.ToLower(firstRiskString(riskMapValue(key, "Status", "status", "State", "state")))
		switch status {
		case "active", "enabled", "enable":
			active++
			if masked := riskMaskedAccessKeyID(firstRiskString(riskMapValue(key, "AccessKeyId", "AccessKeyID", "accessKeyId", "access_key_id"))); masked != "" {
				activeIDs = append(activeIDs, masked)
			}
		case "inactive", "disabled", "disable", "deleted":
			inactive++
		}
	}
	return active, inactive, uniqueStrings(activeIDs)
}

func riskPolicySummaries(attributes map[string]any) []riskPolicySummary {
	rawPolicies := riskNormalizeList(riskMapValue(attributes, "Policies", "policies"))
	policies := make([]riskPolicySummary, 0, len(rawPolicies))
	for _, raw := range rawPolicies {
		rawObject := riskObject(raw)
		policy := firstRiskObject(riskMapValue(rawObject, "Policy", "policy"), rawObject)
		statements := riskPolicyDocumentStatements(rawObject, policy)
		policies = append(policies, riskPolicySummary{
			Name:             firstRiskString(riskMapValue(policy, "PolicyName", "policyName", "name")),
			Statements:       statements,
			SourceGuard:      riskStatementsHaveDenySourceGuard(statements),
			SourceConditions: riskSourceConditionsFromStatements(statements),
		})
	}
	return policies
}

func riskPolicyDocumentStatements(rawObject map[string]any, policy map[string]any) []map[string]any {
	version := firstRiskObject(
		riskMapValue(rawObject, "DefaultPolicyVersion", "defaultPolicyVersion"),
		riskMapValue(policy, "DefaultPolicyVersion", "defaultPolicyVersion"),
		riskMapValue(rawObject, "PolicyVersion", "policyVersion"),
		policy,
	)
	document := firstRiskDefined(
		riskMapValue(version, "PolicyDocument", "policyDocument"),
		riskMapValue(policy, "PolicyDocument", "policyDocument"),
		riskMapValue(rawObject, "PolicyDocument", "policyDocument"),
	)
	return riskPolicyStatements(document)
}

func riskPolicyDataServices(policies []riskPolicySummary) []riskPolicyService {
	services := map[string]riskPolicyService{}
	for _, policy := range policies {
		if len(policy.Statements) == 0 {
			riskAddServicesFromPolicyName(services, policy.Name, false, policy.Name)
			continue
		}
		for _, statement := range policy.Statements {
			if strings.ToLower(firstRiskString(riskMapValue(statement, "Effect", "effect"))) != "allow" {
				continue
			}
			sourceRestricted := riskStatementHasSourceRestriction(statement)
			resources := riskPolicyResources(statement)
			for _, action := range riskPolicyActions(statement) {
				riskAddServiceFromAction(services, action, sourceRestricted, resources, policy.Name)
			}
		}
	}
	result := make([]riskPolicyService, 0, len(services))
	for _, service := range services {
		service.ResourcePatterns = uniqueStrings(service.ResourcePatterns)
		service.PolicyNames = uniqueStrings(service.PolicyNames)
		result = append(result, service)
	}
	sort.Slice(result, func(i, j int) bool {
		if riskServiceRank(result[i].Level) != riskServiceRank(result[j].Level) {
			return riskServiceRank(result[i].Level) > riskServiceRank(result[j].Level)
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func riskAddServicesFromPolicyName(services map[string]riskPolicyService, name string, sourceRestricted bool, policyName string) {
	normalized := strings.ToLower(name)
	if normalized == "" {
		return
	}
	if strings.Contains(normalized, "administratoraccess") {
		for _, service := range riskKnownDataServices() {
			riskAddDataService(services, service, "full access", sourceRestricted, []string{"*"}, policyName)
		}
		return
	}
	for _, matcher := range riskServiceNameMatchers() {
		if strings.Contains(normalized, matcher[0]) {
			level := "full access"
			if strings.Contains(normalized, "readonly") || strings.Contains(normalized, "readonlyaccess") {
				level = "read access"
			}
			riskAddDataService(services, matcher[1], level, sourceRestricted, []string{"*"}, policyName)
		}
	}
}

func riskAddServiceFromAction(services map[string]riskPolicyService, action string, sourceRestricted bool, resources []string, policyName string) {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" {
		return
	}
	if normalized == "*" || normalized == "*:*" {
		for _, service := range riskKnownDataServices() {
			riskAddDataService(services, service, "full access", sourceRestricted, resources, policyName)
		}
		return
	}
	service := riskActionServiceName(normalized)
	if service == "" {
		return
	}
	riskAddDataService(services, service, riskActionPermissionLevel(normalized), sourceRestricted, resources, policyName)
}

func riskAddDataService(services map[string]riskPolicyService, name string, level string, sourceRestricted bool, resources []string, policyName string) {
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	pathKind := riskCredentialPathKind(name, level)
	existing, ok := services[name]
	if !ok || riskServiceRank(level) > riskServiceRank(existing.Level) {
		services[name] = riskPolicyService{
			Name:             name,
			Level:            level,
			PathKind:         pathKind,
			SourceRestricted: sourceRestricted,
			ResourcePatterns: resources,
			PolicyNames:      []string{policyName},
		}
		return
	}
	existing.SourceRestricted = existing.SourceRestricted && sourceRestricted
	existing.ResourcePatterns = append(existing.ResourcePatterns, resources...)
	existing.PolicyNames = append(existing.PolicyNames, policyName)
	if riskServiceRank(level) == riskServiceRank(existing.Level) && riskCredentialPathRank(pathKind) > riskCredentialPathRank(existing.PathKind) {
		existing.PathKind = pathKind
	}
	services[name] = existing
}

func riskPublicPolicySummary(value any, policyStatusPublic bool, hasPolicyStatus bool, allowConditionalPublic bool) struct {
	Public         bool
	Read           bool
	Write          bool
	StatementCount int
} {
	statements := riskPolicyStatements(value)
	publicStatements := make([]map[string]any, 0)
	for _, statement := range statements {
		if strings.ToLower(firstRiskString(riskMapValue(statement, "Effect", "effect"))) != "allow" {
			continue
		}
		if !riskStatementAllowsPublicPrincipal(statement) {
			continue
		}
		if allowConditionalPublic {
			if riskStatementHasRestrictivePublicCondition(statement) {
				continue
			}
		} else if !riskConditionEmpty(riskMapValue(statement, "Condition", "condition")) {
			continue
		}
		publicStatements = append(publicStatements, statement)
	}
	actions := make([]string, 0)
	for _, statement := range publicStatements {
		actions = append(actions, riskPolicyActions(statement)...)
	}
	public := len(publicStatements) > 0
	if hasPolicyStatus {
		public = policyStatusPublic
	}
	return struct {
		Public         bool
		Read           bool
		Write          bool
		StatementCount int
	}{
		Public:         public,
		Read:           riskActionsIncludeRead(actions),
		Write:          riskActionsIncludeWrite(actions),
		StatementCount: len(publicStatements),
	}
}

func riskPolicyStatements(value any) []map[string]any {
	parsed := riskParseJSONValue(value)
	switch typed := parsed.(type) {
	case []any:
		statements := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if object := riskObject(item); len(object) > 0 {
				statements = append(statements, object)
			}
		}
		return statements
	case map[string]any:
		statement := riskParseJSONValue(firstRiskDefined(
			riskMapValue(typed, "Statement", "statement"),
			riskMapValue(typed, "Statements", "statements"),
		))
		switch typedStatement := statement.(type) {
		case []any:
			statements := make([]map[string]any, 0, len(typedStatement))
			for _, item := range typedStatement {
				if object := riskObject(item); len(object) > 0 {
					statements = append(statements, object)
				}
			}
			return statements
		case map[string]any:
			return []map[string]any{typedStatement}
		default:
			if _, ok := typed["Effect"]; ok {
				return []map[string]any{typed}
			}
			if _, ok := typed["effect"]; ok {
				return []map[string]any{typed}
			}
		}
	}
	return nil
}

func riskPolicyActions(statement map[string]any) []string {
	return flattenRiskStrings(riskMapValue(statement, "Action", "action"))
}

func riskPolicyResources(statement map[string]any) []string {
	resources := flattenRiskStrings(firstRiskDefined(riskMapValue(statement, "Resource", "resource"), "*"))
	if len(resources) == 0 {
		return []string{"*"}
	}
	return resources
}

func riskStatementAllowsPublicPrincipal(statement map[string]any) bool {
	principals := flattenRiskStrings(riskMapValue(statement, "Principal", "principal"))
	for _, principal := range principals {
		if strings.TrimSpace(principal) == "*" {
			return true
		}
	}
	return false
}

func riskStatementHasRestrictivePublicCondition(statement map[string]any) bool {
	condition := riskMapValue(statement, "Condition", "condition")
	return riskConditionRestrictsSourceVPC(condition) || riskConditionRestrictsSourceIP(condition) || riskConditionRestrictsAccessID(condition)
}

func riskStatementHasSourceRestriction(statement map[string]any) bool {
	condition := riskMapValue(statement, "Condition", "condition")
	return riskConditionRestrictsSourceVPC(condition) || riskConditionRestrictsSourceIP(condition) || riskConditionRestrictsAccessID(condition)
}

func riskStatementsHaveDenySourceGuard(statements []map[string]any) bool {
	for _, statement := range statements {
		if strings.ToLower(firstRiskString(riskMapValue(statement, "Effect", "effect"))) == "deny" && riskStatementHasSourceRestriction(statement) {
			return true
		}
	}
	return false
}

func riskPoliciesHaveSourceGuard(policies []riskPolicySummary) bool {
	for _, policy := range policies {
		if policy.SourceGuard {
			return true
		}
	}
	return false
}

func riskPolicySourceGuards(policies []riskPolicySummary) []riskPolicySourceGuard {
	guards := make([]riskPolicySourceGuard, 0)
	for _, policy := range policies {
		for _, statement := range policy.Statements {
			if strings.ToLower(firstRiskString(riskMapValue(statement, "Effect", "effect"))) != "deny" {
				continue
			}
			if !riskStatementHasSourceRestriction(statement) {
				continue
			}
			services := riskServicesForPolicyActions(riskPolicyActions(statement))
			if len(services) == 0 {
				continue
			}
			resources := riskPolicyResources(statement)
			conditions := riskSourceConditionsFromStatements([]map[string]any{statement})
			for _, service := range services {
				guards = append(guards, riskPolicySourceGuard{
					Service:          service,
					ResourcePatterns: resources,
					Conditions:       conditions,
				})
			}
		}
	}
	return guards
}

func riskServicesForPolicyActions(actions []string) []string {
	services := make([]string, 0)
	for _, action := range actions {
		normalized := strings.ToLower(strings.TrimSpace(action))
		if normalized == "" {
			continue
		}
		if normalized == "*" || normalized == "*:*" {
			return riskKnownDataServices()
		}
		if service := riskActionServiceName(normalized); service != "" {
			services = append(services, service)
		}
	}
	return uniqueStrings(services)
}

func riskPolicySourceConditions(policies []riskPolicySummary) []riskSourceCondition {
	byKey := map[string][]string{}
	for _, policy := range policies {
		for _, condition := range policy.SourceConditions {
			byKey[condition.Key] = append(byKey[condition.Key], condition.Values...)
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	conditions := make([]riskSourceCondition, 0, len(keys))
	for _, key := range keys {
		conditions = append(conditions, riskSourceCondition{
			Key:    key,
			Values: compactStringList(uniqueStrings(byKey[key]), 8),
		})
	}
	return conditions
}

func riskPolicyDocumentCount(policies []riskPolicySummary) int {
	count := 0
	for _, policy := range policies {
		if len(policy.Statements) > 0 {
			count++
		}
	}
	return count
}

func riskSourceConditionsFromStatements(statements []map[string]any) []riskSourceCondition {
	keys := []string{"acs:SourceIp", "acs:SourceVpc", "acs:SourceVpcId", "acs:AccessId"}
	byKey := map[string][]string{}
	for _, statement := range statements {
		condition := riskMapValue(statement, "Condition", "condition")
		for _, key := range keys {
			values := riskConditionValues(condition, key)
			if len(values) == 0 {
				continue
			}
			if key == "acs:AccessId" {
				for i := range values {
					values[i] = riskMaskedAccessKeyID(values[i])
				}
			}
			byKey[key] = append(byKey[key], values...)
		}
	}
	conditions := make([]riskSourceCondition, 0, len(byKey))
	for _, key := range keys {
		values := compactStringList(uniqueStrings(byKey[key]), 8)
		if len(values) == 0 {
			continue
		}
		conditions = append(conditions, riskSourceCondition{Key: key, Values: values})
	}
	return conditions
}

func riskSourceACLStatus(identity riskIdentitySummary, service riskPolicyService, target model.Asset) string {
	if service.SourceRestricted || riskSourceGuardMatchesTarget(identity.SourceGuards, service, target) {
		return "restricted"
	}
	if identity.PolicyDocCount == 0 {
		return "not_collected"
	}
	return "unrestricted"
}

func riskSourceGuardMatchesTarget(guards []riskPolicySourceGuard, service riskPolicyService, target model.Asset) bool {
	for _, guard := range guards {
		if guard.Service != service.Name {
			continue
		}
		guardService := riskPolicyService{
			Name:             guard.Service,
			ResourcePatterns: guard.ResourcePatterns,
		}
		if riskResourceMatchesService(guardService, target) {
			return true
		}
	}
	return false
}

func riskMaskedAccessKeyID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 4 {
		return "[redacted]"
	}
	return "****" + value[len(value)-4:]
}

func riskConditionRestrictsSourceVPC(condition any) bool {
	for _, value := range riskConditionValues(condition, "acs:SourceVpc", "acs:SourceVpcId") {
		text := strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(text, "vpc-") && !strings.Contains(text, "*") {
			return true
		}
	}
	return false
}

func riskConditionRestrictsAccessID(condition any) bool {
	for _, value := range riskConditionValues(condition, "acs:AccessId") {
		text := strings.TrimSpace(value)
		if text != "" && text != "*" && !strings.Contains(text, "*") {
			return true
		}
	}
	return false
}

func riskConditionRestrictsSourceIP(condition any) bool {
	for _, value := range riskConditionValues(condition, "acs:SourceIp") {
		text := strings.TrimSpace(value)
		if text == "" || strings.Contains(text, "*") || riskAnySource(text) {
			continue
		}
		if prefix, ok := cidrPrefixLength(text); ok {
			if strings.Contains(text, ":") {
				if prefix >= 32 {
					return true
				}
			} else if prefix >= 8 {
				return true
			}
			continue
		}
		return true
	}
	return false
}

func riskConditionValues(condition any, keys ...string) []string {
	values := make([]string, 0)
	keySet := map[string]bool{}
	for _, key := range keys {
		keySet[strings.ToLower(key)] = true
	}
	riskWalkObjects(condition, func(node map[string]any) {
		for key, value := range node {
			if keySet[strings.ToLower(key)] {
				values = append(values, flattenRiskStrings(value)...)
			}
		}
	})
	return values
}

func riskConditionEmpty(condition any) bool {
	parsed := riskParseJSONValue(condition)
	if parsed == nil {
		return true
	}
	object, ok := parsed.(map[string]any)
	return ok && len(object) == 0
}

func riskActionsIncludeRead(actions []string) bool {
	if len(actions) == 0 {
		return true
	}
	for _, action := range actions {
		normalized := strings.ToLower(action)
		if normalized == "*" || strings.HasSuffix(normalized, ":*") || strings.Contains(normalized, ":get") || strings.Contains(normalized, ":list") || strings.Contains(normalized, ":read") || strings.Contains(normalized, ":query") {
			return true
		}
	}
	return false
}

func riskActionsIncludeWrite(actions []string) bool {
	for _, action := range actions {
		normalized := strings.ToLower(action)
		if normalized == "*" || strings.HasSuffix(normalized, ":*") || strings.Contains(normalized, ":put") || strings.Contains(normalized, ":post") || strings.Contains(normalized, ":delete") || strings.Contains(normalized, ":create") || strings.Contains(normalized, ":set") {
			return true
		}
	}
	return false
}

func riskHasPublicDataEndpoint(attributes map[string]any) bool {
	found := false
	riskWalkObjects(attributes, func(node map[string]any) {
		if found {
			return
		}
		networkType := strings.ToLower(firstRiskString(
			riskMapValue(node, "DBInstanceNetType", "dbInstanceNetType"),
			riskMapValue(node, "IPType", "ipType"),
			riskMapValue(node, "NetType", "netType"),
			riskMapValue(node, "NetworkType", "networkType"),
			riskMapValue(node, "ConnectionStringType", "connectionStringType"),
		))
		if networkType != "" && (riskIsPublicAddressType(networkType) || regexp.MustCompile(`internet|public|extranet|wan`).MatchString(networkType)) {
			found = true
			return
		}
		for key, value := range node {
			keyLower := strings.ToLower(key)
			if !strings.Contains(keyLower, "public") && !strings.Contains(keyLower, "internet") && !strings.Contains(keyLower, "extranet") {
				continue
			}
			if riskTruthy(value) {
				found = true
				return
			}
			text := firstRiskString(value)
			if text != "" && text != "false" && text != "0" {
				found = true
				return
			}
		}
	})
	return found
}

func riskCollectAccessListEntries(attributes map[string]any) []string {
	entries := make([]string, 0)
	riskWalkObjects(attributes, func(node map[string]any) {
		for _, key := range []string{
			"SecurityIPList",
			"SecurityIpList",
			"securityIPList",
			"securityIpList",
			"SecurityIps",
			"securityIps",
			"Whitelist",
			"whiteList",
			"WhiteList",
			"IPWhitelist",
			"ipWhitelist",
		} {
			if value, ok := node[key]; ok {
				entries = append(entries, splitRiskListValues(value)...)
			}
		}
	})
	return uniqueStrings(entries)
}

func riskResourceMatchesService(service riskPolicyService, target model.Asset) bool {
	patterns := service.ResourcePatterns
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}
	targetIDs := []string{
		target.ResourceID,
		target.ID,
		target.Name,
		nativeRiskID(target.ResourceID),
		nativeRiskID(target.ID),
	}
	for i, value := range targetIDs {
		targetIDs[i] = strings.ToLower(strings.TrimSpace(value))
	}
	for _, pattern := range patterns {
		normalized := strings.ToLower(strings.TrimSpace(pattern))
		if normalized == "" || normalized == "*" || normalized == "*:*" {
			return true
		}
		for _, id := range targetIDs {
			if id != "" && (strings.Contains(normalized, id) || strings.Contains(id, normalized)) {
				return true
			}
		}
		if strings.Contains(normalized, "*") && riskPatternAppliesToAllServiceResources(normalized, service.Name) {
			return true
		}
		if strings.Contains(normalized, "*") {
			re := regexp.MustCompile("^" + strings.Join(regexpQuoteSplit(normalized, "*"), ".*") + "$")
			for _, id := range targetIDs {
				if id != "" && re.MatchString(id) {
					return true
				}
			}
		}
	}
	return false
}

func riskPatternAppliesToAllServiceResources(pattern string, service string) bool {
	if !riskPatternAppliesToService(pattern, service) {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(pattern))
	if normalized == "*" || normalized == "*:*" {
		return true
	}
	parts := strings.SplitN(normalized, ":", 5)
	if len(parts) != 5 {
		return false
	}
	relative := strings.Trim(parts[4], "/")
	if relative == "" {
		return false
	}
	if relative == "*" || relative == "*/*" {
		return true
	}
	tokens := strings.Split(relative, "/")
	hasWildcard := false
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if token == "*" {
			hasWildcard = true
			continue
		}
		if riskIsServiceResourceTypeToken(service, token) {
			continue
		}
		return false
	}
	return hasWildcard
}

func riskIsServiceResourceTypeToken(service string, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	for _, allowed := range riskServiceResourceTypeTokens(service) {
		if token == allowed {
			return true
		}
	}
	return false
}

func riskServiceResourceTypeTokens(service string) []string {
	switch service {
	case "SLS":
		return []string{"project", "logstore", "dashboard", "machinegroup", "savedsearch", "shipper"}
	case "RDS":
		return []string{"dbinstance", "dbinstanceid", "database", "backup", "account"}
	case "Redis":
		return []string{"instance", "dbinstance", "dbinstanceid", "account"}
	case "MongoDB":
		return []string{"dbinstance", "instance", "account"}
	case "PolarDB":
		return []string{"cluster", "dbcluster", "dbinstance", "database", "account"}
	case "ClickHouse":
		return []string{"dbcluster", "cluster", "instance", "account"}
	case "Lindorm":
		return []string{"instance", "cluster"}
	case "HBase":
		return []string{"cluster", "instance"}
	case "Elasticsearch":
		return []string{"instance", "cluster"}
	case "Kafka":
		return []string{"instance", "topic", "consumerGroup", "consumergroup"}
	case "RocketMQ":
		return []string{"instance", "topic", "group", "consumergroup"}
	default:
		return nil
	}
}

func riskPatternAppliesToService(pattern string, service string) bool {
	service = strings.ToLower(service)
	switch service {
	case "OSS":
		return strings.Contains(pattern, "oss")
	case "SLS":
		return strings.Contains(pattern, "log") || strings.Contains(pattern, "sls")
	case "RDS":
		return strings.Contains(pattern, "rds") || strings.Contains(pattern, "dbs") || strings.Contains(pattern, "adb")
	case "Redis":
		return strings.Contains(pattern, "kvstore") || strings.Contains(pattern, "redis")
	case "MongoDB":
		return strings.Contains(pattern, "dds") || strings.Contains(pattern, "mongodb")
	case "PolarDB":
		return strings.Contains(pattern, "polardb")
	case "ClickHouse":
		return strings.Contains(pattern, "clickhouse")
	case "Lindorm":
		return strings.Contains(pattern, "lindorm") || strings.Contains(pattern, "hitsdb")
	case "HBase":
		return strings.Contains(pattern, "hbase")
	case "Elasticsearch":
		return strings.Contains(pattern, "elasticsearch") || strings.Contains(pattern, "es")
	case "Kafka":
		return strings.Contains(pattern, "alikafka") || strings.Contains(pattern, "kafka")
	case "RocketMQ":
		return strings.Contains(pattern, "rocketmq") || strings.Contains(pattern, "ons") || strings.Contains(pattern, "mq")
	default:
		return false
	}
}

func riskActionServiceName(action string) string {
	prefix := strings.ToLower(strings.Split(action, ":")[0])
	switch prefix {
	case "oss":
		return "OSS"
	case "log", "sls":
		return "SLS"
	case "rds", "dbs", "hdm", "adb":
		return "RDS"
	case "kvstore", "redis":
		return "Redis"
	case "dds", "mongodb":
		return "MongoDB"
	case "polardb":
		return "PolarDB"
	case "clickhouse":
		return "ClickHouse"
	case "hitsdb", "lindorm":
		return "Lindorm"
	case "hbase":
		return "HBase"
	case "elasticsearch", "es":
		return "Elasticsearch"
	case "alikafka", "kafka":
		return "Kafka"
	case "mq", "ons", "rocketmq":
		return "RocketMQ"
	default:
		return ""
	}
}

func riskActionPermissionLevel(action string) string {
	normalized := strings.ToLower(action)
	if strings.Contains(normalized, "*") {
		return "full access"
	}
	operation := normalized
	if parts := strings.SplitN(normalized, ":", 2); len(parts) == 2 {
		operation = parts[1]
	}
	if regexp.MustCompile(`^(put|post|delete|create|modify|update|set|attach|grant|reset|add|remove|allocate|release)`).MatchString(operation) {
		return "manage access"
	}
	return "read access"
}

func riskCredentialPathKind(service string, level string) string {
	if service == "OSS" || service == "SLS" {
		return "data-plane access"
	}
	if level == "read access" {
		return "management-plane visibility"
	}
	return "management-plane change"
}

func riskCredentialPathRank(kind string) int {
	switch kind {
	case "management-plane visibility":
		return 1
	case "management-plane change":
		return 2
	case "data-plane access":
		return 3
	default:
		return 0
	}
}

func riskServiceRank(level string) int {
	switch level {
	case "read access":
		return 1
	case "manage access":
		return 2
	case "full access":
		return 3
	default:
		return 0
	}
}

func riskDataServiceForType(resourceType string) string {
	normalized := compactResourceType(resourceType)
	switch {
	case normalized == "oss" || strings.Contains(normalized, "bucket"):
		return "OSS"
	case normalized == "sls" || normalized == "logservice" || strings.Contains(normalized, "logstore") || strings.Contains(normalized, "logproject"):
		return "SLS"
	case normalized == "redis" || strings.Contains(normalized, "kvstore"):
		return "Redis"
	case normalized == "mongodb" || strings.Contains(normalized, "dds"):
		return "MongoDB"
	case normalized == "polardb":
		return "PolarDB"
	case normalized == "clickhouse":
		return "ClickHouse"
	case normalized == "lindorm" || normalized == "hitsdb":
		return "Lindorm"
	case normalized == "hbase":
		return "HBase"
	case normalized == "elasticsearch":
		return "Elasticsearch"
	case normalized == "kafka" || normalized == "alikafka":
		return "Kafka"
	case normalized == "rocketmq" || normalized == "mq" || normalized == "ons":
		return "RocketMQ"
	case normalized == "rds" || strings.Contains(normalized, "dbinstance") || strings.Contains(normalized, "database") || strings.Contains(normalized, "analyticdb"):
		return "RDS"
	default:
		return ""
	}
}

func canonicalRiskService(value string) string {
	normalized := compactResourceType(value)
	for _, service := range riskKnownDataServices() {
		if compactResourceType(service) == normalized {
			return service
		}
	}
	return strings.TrimSpace(value)
}

func riskKnownDataServices() []string {
	return []string{"OSS", "SLS", "RDS", "Redis", "MongoDB", "PolarDB", "ClickHouse", "Lindorm", "HBase", "Elasticsearch", "Kafka", "RocketMQ"}
}

func riskKnownDataService(service string) bool {
	for _, item := range riskKnownDataServices() {
		if item == service {
			return true
		}
	}
	return false
}

func riskServiceNameMatchers() [][2]string {
	return [][2]string{
		{"oss", "OSS"},
		{"sls", "SLS"},
		{"aliyunlog", "SLS"},
		{"logfullaccess", "SLS"},
		{"logreadonlyaccess", "SLS"},
		{"rds", "RDS"},
		{"kvstore", "Redis"},
		{"redis", "Redis"},
		{"mongodb", "MongoDB"},
		{"dds", "MongoDB"},
		{"polardb", "PolarDB"},
		{"clickhouse", "ClickHouse"},
		{"lindorm", "Lindorm"},
		{"hbase", "HBase"},
		{"elasticsearch", "Elasticsearch"},
		{"alikafka", "Kafka"},
		{"kafka", "Kafka"},
		{"rocketmq", "RocketMQ"},
	}
}

func filterRiskPaths(paths []riskPathView, filter riskPathFilter) []riskPathView {
	filtered := make([]riskPathView, 0, len(paths))
	for _, path := range paths {
		if filter.PathType != "" && path.PathType != filter.PathType {
			continue
		}
		if filter.Service != "" && !strings.EqualFold(path.Service, filter.Service) {
			continue
		}
		if filter.Region != "" && path.Region != filter.Region {
			if path.Source == nil || path.Source.Region != filter.Region {
				continue
			}
		}
		if filter.ResourceType != "" && !sameResourceType(path.Target.ResourceType, filter.ResourceType) {
			if path.Source == nil || !sameResourceType(path.Source.ResourceType, filter.ResourceType) {
				continue
			}
		}
		if filter.Q != "" && !riskPathMatchesQuery(path, filter.Q) {
			continue
		}
		filtered = append(filtered, path)
	}
	return filtered
}

func filterTrafficPaths(paths []trafficPathView, filter riskPathFilter) []trafficPathView {
	filtered := make([]trafficPathView, 0, len(paths))
	for _, path := range paths {
		if filter.PathType != "" && filter.PathType != riskPathPublicTrafficExposure {
			continue
		}
		if filter.Service != "" && !strings.EqualFold(filter.Service, path.Entry.ResourceType) {
			continue
		}
		if filter.Region != "" && path.Region != filter.Region {
			continue
		}
		if filter.ResourceType != "" {
			matches := sameResourceType(path.Entry.ResourceType, filter.ResourceType)
			for _, backend := range path.Backends {
				if backend.Asset != nil && sameResourceType(backend.Asset.ResourceType, filter.ResourceType) {
					matches = true
				}
				for _, group := range backend.SecurityGroups {
					if group.Asset != nil && sameResourceType(group.Asset.ResourceType, filter.ResourceType) {
						matches = true
					}
				}
			}
			if !matches {
				continue
			}
		}
		if filter.Q != "" && !trafficPathMatchesQuery(path, filter.Q) {
			continue
		}
		if filter.Port != "" && !trafficPathMatchesPort(path, filter.Port) {
			continue
		}
		if filter.OpenPolicy != "" && !trafficPathMatchesOpenPolicy(path, filter.OpenPolicy) {
			continue
		}
		filtered = append(filtered, path)
	}
	return filtered
}

func trafficPathMatchesPort(path trafficPathView, port string) bool {
	port = strings.TrimSpace(port)
	if port == "" {
		return true
	}
	for _, listener := range path.Listeners {
		if strings.EqualFold(strings.TrimSpace(listener.Port), port) {
			return true
		}
	}
	for _, backend := range path.Backends {
		if strings.EqualFold(strings.TrimSpace(backend.Port), port) {
			return true
		}
		for _, group := range backend.SecurityGroups {
			for _, policy := range group.Policies {
				if trafficPolicyMatchesPort(policy, port) {
					return true
				}
			}
			for _, policy := range group.OpenPolicies {
				if trafficPolicyMatchesPort(policy, port) {
					return true
				}
			}
		}
	}
	return false
}

func trafficPolicyMatchesPort(policy trafficSGPolicy, port string) bool {
	value := strings.TrimSpace(policy.Port)
	if value == "" || strings.EqualFold(value, "all") || value == "*" {
		return true
	}
	if strings.EqualFold(value, port) {
		return true
	}
	for _, separator := range []string{"/", "-"} {
		parts := strings.Split(value, separator)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == port && strings.TrimSpace(parts[1]) == port {
			return true
		}
	}
	return false
}

func trafficPathMatchesOpenPolicy(path trafficPathView, value string) bool {
	wantOpen, ok := parseRiskBool(value)
	if !ok {
		return true
	}
	hasOpen := path.OpenPolicyCount > 0
	return hasOpen == wantOpen
}

func parseRiskBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "open", "wide_open":
		return true, true
	case "0", "false", "no", "n", "closed", "restricted":
		return false, true
	default:
		return false, false
	}
}

func trafficPathMatchesQuery(path trafficPathView, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	values := []string{
		path.ID,
		path.PathType,
		path.Severity,
		path.Entry.ResourceID,
		path.Entry.Name,
		path.Entry.ResourceType,
		path.Address,
	}
	for _, backend := range path.Backends {
		values = append(values, backend.ResourceID, backend.Name, backend.NativeID)
		for _, group := range backend.SecurityGroups {
			values = append(values, group.ResourceID, group.Name, group.NativeID)
		}
	}
	values = append(values, path.Signals...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func riskPathMatchesQuery(path riskPathView, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	values := []string{
		path.ID,
		path.PathType,
		path.Severity,
		path.Service,
		path.Target.ID,
		path.Target.ResourceID,
		path.Target.Name,
		path.Target.ResourceType,
	}
	if path.Source != nil {
		values = append(values, path.Source.ID, path.Source.ResourceID, path.Source.Name, path.Source.ResourceType)
	}
	values = append(values, path.Signals...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func sortTrafficPaths(paths []trafficPathView) {
	sort.Slice(paths, func(i, j int) bool {
		if riskSeverityRank(paths[i].Severity) != riskSeverityRank(paths[j].Severity) {
			return riskSeverityRank(paths[i].Severity) > riskSeverityRank(paths[j].Severity)
		}
		if paths[i].OpenPolicyCount != paths[j].OpenPolicyCount {
			return paths[i].OpenPolicyCount > paths[j].OpenPolicyCount
		}
		return paths[i].Entry.ResourceID < paths[j].Entry.ResourceID
	})
}

func sortRiskPaths(paths []riskPathView) {
	sort.Slice(paths, func(i, j int) bool {
		if riskSeverityRank(paths[i].Severity) != riskSeverityRank(paths[j].Severity) {
			return riskSeverityRank(paths[i].Severity) > riskSeverityRank(paths[j].Severity)
		}
		if paths[i].PathType != paths[j].PathType {
			return paths[i].PathType < paths[j].PathType
		}
		return paths[i].Target.ResourceID < paths[j].Target.ResourceID
	})
}

func summarizeRiskPaths(paths []riskPathView) riskPathSummary {
	summary := riskPathSummary{
		Total:          len(paths),
		ServiceCounts:  map[string]int{},
		SeverityCounts: map[string]int{},
	}
	for _, path := range paths {
		summary.ServiceCounts[path.Service]++
		summary.SeverityCounts[path.Severity]++
		switch path.PathType {
		case riskPathAnonymousPublicDataAccess:
			summary.AnonymousPublicDataAccess++
		case riskPathCredentialDataAccess:
			summary.CredentialDataAccess++
		case riskPathCredentialControlPlaneExposure:
			summary.CredentialControlPlaneExposure++
		case riskPathDirectNetworkExposure:
			summary.DirectNetworkExposure++
		case riskPathBroadNetworkACL:
			summary.BroadNetworkACL++
		}
	}
	return summary
}

func paginateTrafficPaths(paths []trafficPathView, offset int, limit int) []trafficPathView {
	if offset >= len(paths) {
		return []trafficPathView{}
	}
	end := len(paths)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return paths[offset:end]
}

func paginateRiskPaths(paths []riskPathView, offset int, limit int) []riskPathView {
	if offset >= len(paths) {
		return []riskPathView{}
	}
	end := len(paths)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return paths[offset:end]
}

func groupRiskPaths(paths []riskPathView) []riskPathGroup {
	groupsByID := map[string]*riskPathGroup{}
	for _, path := range paths {
		groupID := riskPathGroupID(path)
		group, ok := groupsByID[groupID]
		if !ok {
			group = &riskPathGroup{
				ID:        groupID,
				PathType:  path.PathType,
				Severity:  path.Severity,
				Service:   path.Service,
				AccountID: path.AccountID,
				Provider:  path.Provider,
				Region:    path.Region,
				Source:    path.Source,
				Evidence:  map[string]any{},
			}
			for key, value := range path.Evidence {
				group.Evidence[key] = value
			}
			groupsByID[groupID] = group
		}
		if riskSeverityRank(path.Severity) > riskSeverityRank(group.Severity) {
			group.Severity = path.Severity
		}
		group.Signals = uniqueStrings(append(group.Signals, path.Signals...))
		if !riskGroupHasTarget(group.Targets, path.Target) {
			group.Targets = append(group.Targets, path.Target)
		}
	}
	groups := make([]riskPathGroup, 0, len(groupsByID))
	for _, group := range groupsByID {
		sort.Slice(group.Targets, func(i, j int) bool {
			return group.Targets[i].ResourceID < group.Targets[j].ResourceID
		})
		group.TargetCount = len(group.Targets)
		if group.Evidence == nil {
			group.Evidence = map[string]any{}
		}
		group.Evidence["target_count"] = group.TargetCount
		if len(group.Targets) > 10 {
			group.Targets = group.Targets[:10]
		}
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if riskSeverityRank(groups[i].Severity) != riskSeverityRank(groups[j].Severity) {
			return riskSeverityRank(groups[i].Severity) > riskSeverityRank(groups[j].Severity)
		}
		if groups[i].TargetCount != groups[j].TargetCount {
			return groups[i].TargetCount > groups[j].TargetCount
		}
		return groups[i].ID < groups[j].ID
	})
	return groups
}

func riskPathGroupID(path riskPathView) string {
	if path.Source != nil {
		return sanitizeRiskPathID(strings.Join([]string{
			"group",
			path.PathType,
			path.Service,
			path.Source.ResourceID,
		}, ":"))
	}
	return sanitizeRiskPathID(strings.Join([]string{
		"group",
		path.PathType,
		path.Service,
		path.Target.ResourceID,
	}, ":"))
}

func riskGroupHasTarget(targets []model.AssetSummary, target model.AssetSummary) bool {
	for _, existing := range targets {
		if existing.ID != "" && existing.ID == target.ID {
			return true
		}
		if existing.ResourceID != "" && existing.ResourceID == target.ResourceID {
			return true
		}
	}
	return false
}

func paginateRiskPathGroups(groups []riskPathGroup, offset int, limit int) []riskPathGroup {
	if offset >= len(groups) {
		return []riskPathGroup{}
	}
	end := len(groups)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return groups[offset:end]
}

func dedupeRiskPaths(paths []riskPathView) []riskPathView {
	seen := map[string]bool{}
	result := make([]riskPathView, 0, len(paths))
	for _, path := range paths {
		if seen[path.ID] {
			continue
		}
		seen[path.ID] = true
		result = append(result, path)
	}
	return result
}

func riskPathID(path riskPathView) string {
	parts := []string{
		path.PathType,
		path.Service,
		path.Target.ResourceID,
	}
	if path.Source != nil {
		parts = append(parts, path.Source.ResourceID)
	}
	return sanitizeRiskPathID(strings.Join(parts, ":"))
}

func sanitizeRiskPathID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			continue
		}
		builder.WriteRune('-')
	}
	return strings.Trim(builder.String(), "-")
}

func riskSeverityRank(severity string) int {
	switch strings.ToLower(severity) {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func riskAssetAttributes(asset model.Asset) map[string]any {
	root := riskObject(asset.Properties)
	if attributes := riskObject(riskMapValue(root, "attributes", "Attributes")); len(attributes) > 0 {
		return attributes
	}
	return root
}

func riskObject(value any) map[string]any {
	parsed := riskParseJSONValue(value)
	switch typed := parsed.(type) {
	case map[string]any:
		return typed
	case json.RawMessage:
		var object map[string]any
		if err := json.Unmarshal(typed, &object); err == nil {
			return object
		}
	case []byte:
		var object map[string]any
		if err := json.Unmarshal(typed, &object); err == nil {
			return object
		}
	}
	return map[string]any{}
}

func riskMapValue(object map[string]any, keys ...string) any {
	if len(object) == 0 {
		return nil
	}
	for _, key := range keys {
		if value, ok := object[key]; ok {
			return value
		}
	}
	for objectKey, value := range object {
		for _, key := range keys {
			if strings.EqualFold(objectKey, key) {
				return value
			}
		}
	}
	return nil
}

func firstRiskObject(values ...any) map[string]any {
	for _, value := range values {
		object := riskObject(value)
		if len(object) > 0 {
			return object
		}
	}
	return map[string]any{}
}

func firstRiskDefined(values ...any) any {
	for _, value := range values {
		if value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case []any:
			if len(typed) == 0 {
				continue
			}
		case map[string]any:
			if len(typed) == 0 {
				continue
			}
		}
		return value
	}
	return nil
}

func firstRiskString(values ...any) string {
	for _, value := range values {
		parsed := riskParseJSONValue(value)
		switch typed := parsed.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case fmt.Stringer:
			text := strings.TrimSpace(typed.String())
			if text != "" {
				return text
			}
		case bool:
			if typed {
				return "true"
			}
			return "false"
		case float64:
			return fmt.Sprintf("%v", typed)
		case int:
			return fmt.Sprintf("%d", typed)
		default:
			text := strings.TrimSpace(fmt.Sprintf("%v", typed))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func riskParseJSONValue(value any) any {
	switch typed := value.(type) {
	case json.RawMessage:
		if len(typed) == 0 {
			return nil
		}
		var parsed any
		if err := json.Unmarshal(typed, &parsed); err == nil {
			return parsed
		}
	case []byte:
		if len(typed) == 0 {
			return nil
		}
		var parsed any
		if err := json.Unmarshal(typed, &parsed); err == nil {
			return parsed
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var parsed any
			if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
				return parsed
			}
		}
	}
	return value
}

func riskNormalizeList(value any) []any {
	parsed := riskParseJSONValue(value)
	if parsed == nil {
		return nil
	}
	switch typed := parsed.(type) {
	case []any:
		return typed
	case map[string]any:
		for _, value := range typed {
			if list, ok := riskParseJSONValue(value).([]any); ok {
				return list
			}
		}
		return []any{typed}
	default:
		return []any{typed}
	}
}

func flattenRiskStrings(value any) []string {
	parsed := riskParseJSONValue(value)
	switch typed := parsed.(type) {
	case nil:
		return nil
	case []any:
		values := make([]string, 0)
		for _, item := range typed {
			values = append(values, flattenRiskStrings(item)...)
		}
		return values
	case map[string]any:
		values := make([]string, 0)
		for _, item := range typed {
			values = append(values, flattenRiskStrings(item)...)
		}
		return values
	default:
		text := firstRiskString(typed)
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func splitRiskListValues(value any) []string {
	values := make([]string, 0)
	for _, item := range flattenRiskStrings(value) {
		for _, part := range regexp.MustCompile(`[,\s;]+`).Split(item, -1) {
			if strings.TrimSpace(part) != "" {
				values = append(values, strings.TrimSpace(part))
			}
		}
	}
	return values
}

func riskWalkObjects(value any, visitor func(map[string]any)) {
	seen := map[any]bool{}
	var walk func(any)
	walk = func(current any) {
		parsed := riskParseJSONValue(current)
		switch typed := parsed.(type) {
		case map[string]any:
			if seen[fmt.Sprintf("%p", &typed)] {
				return
			}
			seen[fmt.Sprintf("%p", &typed)] = true
			visitor(typed)
			for _, item := range typed {
				walk(item)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(value)
}

func riskTruthy(value any) bool {
	parsed := riskParseJSONValue(value)
	switch typed := parsed.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "y", "enabled", "enable", "on", "public", "internet", "extranet":
			return true
		default:
			return false
		}
	case float64:
		return typed != 0
	case int:
		return typed != 0
	default:
		return parsed != nil
	}
}

func riskOptionalBool(value any) (bool, bool) {
	if value == nil {
		return false, false
	}
	parsed := riskParseJSONValue(value)
	switch typed := parsed.(type) {
	case bool:
		return typed, true
	case string:
		trimmed := strings.ToLower(strings.TrimSpace(typed))
		if trimmed == "" {
			return false, false
		}
		switch trimmed {
		case "true", "1", "yes", "y", "enabled", "enable", "on":
			return true, true
		case "false", "0", "no", "n", "disabled", "disable", "off":
			return false, true
		}
	case float64:
		return typed != 0, true
	}
	return false, false
}

func riskAnySource(source string) bool {
	value := strings.ToLower(strings.TrimSpace(source))
	return value == "*" || value == "0.0.0.0/0" || value == "::/0" || value == "0.0.0.0" || value == "all" || value == "any"
}

func riskIsPublicAddressType(value string) bool {
	normalized := compactResourceType(value)
	return normalized == "internet" || normalized == "public" || normalized == "publicnetwork" || normalized == "extranet"
}

func riskIsPublicIPv4(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

func cidrPrefixLength(value string) (int, bool) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	ones, _ := network.Mask.Size()
	return ones, true
}

func riskIsRAMUser(resourceType string) bool {
	normalized := compactResourceType(resourceType)
	return normalized == "ramuser" || strings.Contains(normalized, "ramuser")
}

func nativeRiskID(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	parts := strings.FieldsFunc(strings.Split(strings.Split(text, "?")[0], "#")[0], func(r rune) bool {
		return r == '/'
	})
	if len(parts) == 0 {
		return text
	}
	return parts[len(parts)-1]
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func compactStringList(values []string, limit int) []string {
	values = uniqueStrings(values)
	if limit > 0 && len(values) > limit {
		return values[:limit]
	}
	return values
}

func redactedAccessListEvidence(values []string) []string {
	values = uniqueStrings(values)
	if len(values) > 8 {
		values = values[:8]
	}
	return values
}

func regexpQuoteSplit(value string, sep string) []string {
	parts := strings.Split(value, sep)
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return parts
}
