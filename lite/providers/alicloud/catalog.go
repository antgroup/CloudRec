package alicloud

import "strings"

const (
	DimensionGlobal   = "global"
	DimensionRegional = "regional"
)

type ResourceSpec struct {
	Type          string
	Normalized    string
	Group         string
	Dimension     string
	CollectorPath string
}

var collectorResourceCatalog = []ResourceSpec{
	{Type: "ACK Cluster", Group: "CONTAINER", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ack/cluster.go"},
	{Type: "ACR", Group: "CONTAINER", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/acr/cr.go"},
	{Type: "ALB", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/loadbalance/alb/alb.go"},
	{Type: "APIG", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/apig/domain.go"},
	{Type: "API Gateway", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cloudapi/apigateway.go"},
	{Type: "API Gateway App", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudapi/api_gateway_app.go"},
	{Type: "ARMS Prometheus", Group: "MONITORING", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/arms/prometheus.go"},
	{Type: "Account", Group: "IDENTITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ims/account.go"},
	{Type: "ActionTrail", Group: "CONFIG", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/actiontrail/actiontrail.go"},
	{Type: "AnalyticDB MySQL", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/AnalyticDB/adbmysql/adb_mysql.go"},
	{Type: "AnalyticDB PostgreSQL", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/AnalyticDB/adbpostgresql/adb_postgresql.go"},
	{Type: "Anycast EIP Address", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/eipanycast/anycast_eip_address.go"},
	{Type: "BPStudio Application", Group: "MIDDLEWARE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/bpstudio/application.go"},
	{Type: "Bastionhost", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/yundun/bastionhost.go"},
	{Type: "CDN", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cdn/cdn.go"},
	{Type: "CEN", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cen/cen.go"},
	{Type: "CERT", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cas/cert.go"},
	{Type: "ClickHouse", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/clickhouse/clickhouse.go"},
	{Type: "Cloudfw", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudfw/cloudfw_instance.go"},
	{Type: "Cloudfw Config", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudfw/cloudfw.go"},
	{Type: "CloudAPI", Group: "CONFIG", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cloudapi/cloudapi.go"},
	{Type: "CloudStorageGateway", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudstoragegateway/gateway.go"},
	{Type: "CloudStorageGateway Storage Bundle", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudstoragegateway/storage_bundle.go"},
	{Type: "DBS Backup Plan", Group: "DATABASE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/dbs/backup_plan.go"},
	{Type: "DCDN Domain", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/dcdn/domain.go"},
	{Type: "DCDN IpaDomain", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/dcdn/ipa_domain.go"},
	{Type: "DMS", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/dms/dms.go"},
	{Type: "DNS", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/dns/dns.go"},
	{Type: "DTS Instance", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/dts/instance.go"},
	{Type: "DataHub Project", Group: "BIGDATA", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/datahub/datahub_project.go"},
	{Type: "DdosCoo", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ddos/ddos.go"},
	{Type: "DomainRR", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/dns/domainrr.go"},
	{Type: "ECI ContainerGroup", Group: "CONTAINER", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/eci/container_group.go"},
	{Type: "ECI ImageCache", Group: "CONTAINER", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/eci/image_cache.go"},
	{Type: "ECP Instance", Group: "CONTAINER", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ecp/instance.go"},
	{Type: "ECS", Group: "COMPUTE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ecs/ecs.go"},
	{Type: "ECS Image", Group: "STORE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ecs/images.go"},
	{Type: "ECS Snapshot", Group: "STORE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ecs/snapshots.go"},
	{Type: "EIP", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/eip/eip.go"},
	{Type: "ENS Eip", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ens/eip.go"},
	{Type: "ENS Instance", Group: "COMPUTE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ens/instance.go"},
	{Type: "ENS LoadBalancer", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ens/loadbalancer.go"},
	{Type: "ENS NatGateway", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ens/nat.go"},
	{Type: "ENS Network", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ens/network.go"},
	{Type: "ESS", Group: "COMPUTE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ess/ess.go"},
	{Type: "Eflo Cluster", Group: "COMPUTE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/eflo/cluster.go"},
	{Type: "Elasticsearch", Group: "BIGDATA", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/elasticsearch/elasticsearch.go"},
	{Type: "Logstash", Group: "LOG", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/elasticsearch/logstash.go"},
	{Type: "FC", Group: "COMPUTE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/fc/fc.go"},
	{Type: "GA Accelerator", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ga/accelerator.go"},
	{Type: "GrafanaWorkspace", Group: "CONFIG", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/arms/grafanaworkspace.go"},
	{Type: "Hbase", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/hbase/hbase.go"},
	{Type: "Hologram Instance", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/hologram/instance.go"},
	{Type: "KMS", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/kms/kms.go"},
	{Type: "Kafka", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/kafka/kafka.go"},
	{Type: "Lindorm", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/hitsdb/lindorm.go"},
	{Type: "Live Domain", Group: "NET", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/live/live_domain.go"},
	{Type: "MaxCompute", Group: "BIGDATA", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/maxcompute/maxcompute.go"},
	{Type: "MSE", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/mse/gateway.go"},
	{Type: "MSE Cluster", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/mse/cluster.go"},
	{Type: "Message Service Queue", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/mns/queue.go"},
	{Type: "MongoDB", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/mongodb/mongodb.go"},
	{Type: "NAS", Group: "STORE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/nas/nas.go"},
	{Type: "NAT", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/nat/nat.go"},
	{Type: "NLB", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/loadbalance/nlb/nlb.go"},
	{Type: "Nat Firewall", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudfw/nat_firewall.go"},
	{Type: "ONS Instance", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ons/instance.go"},
	{Type: "OOS Application", Group: "MIDDLEWARE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/oos/application.go"},
	{Type: "OSS", Group: "STORE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/oss/oss.go"},
	{Type: "OceanBase", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/oceanbase/oceanbase.go"},
	{Type: "OpenSearch AppGroup", Group: "BIGDATA", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/opensearch/appgroup.go"},
	{Type: "Physical Connection", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/physical_connection.go"},
	{Type: "PolarDB", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/polardb/polardb.go"},
	{Type: "PrivateLink", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/pl/pl.go"},
	{Type: "RAM Role", Group: "IDENTITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ram/ram_role.go"},
	{Type: "RAM User", Group: "IDENTITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ram/ram_user.go"},
	{Type: "RDS", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/rds/rds.go"},
	{Type: "RAM Group", Group: "IDENTITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/ram/group.go"},
	{Type: "RTC Application", Group: "MIDDLEWARE", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/rtc/application.go"},
	{Type: "Redis", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/redis/redis.go"},
	{Type: "ResourceCenter", Group: "GOVERNANCE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/resourcecenter/resource_center.go"},
	{Type: "RocketMQ", Group: "MIDDLEWARE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/rocketmq/rocketmq.go"},
	{Type: "SLB", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/loadbalance/slb/slb.go"},
	{Type: "SLS", Group: "STORE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/sls/sls.go"},
	{Type: "SMS Template", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/sms/template.go"},
	{Type: "SWAS", Group: "COMPUTE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/swas/swas.go"},
	{Type: "Sas", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cloudcenter/sas_instance.go"},
	{Type: "Sas Config", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/cloudcenter/sas_config.go"},
	{Type: "Security Group", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/ecs/security_group.go"},
	{Type: "SelectDB", Group: "DATABASE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/db/selectdb/selectdb.go"},
	{Type: "Tablestore", Group: "STORE", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/tablestore/tablestore.go"},
	{Type: "TraceApp", Group: "CONFIG", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/arms/traceapp.go"},
	{Type: "VOD Domain", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vod/domain.go"},
	{Type: "VPC", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/vpc.go"},
	{Type: "VPN Gateway", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/vpn_gateway.go"},
	{Type: "Vpc Firewall", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/cloudfw/vpc_firewall.go"},
	{Type: "VPC Peer Connection", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpcpeer/vpc_peer_connection.go"},
	{Type: "VPN Connection", Group: "NET", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/vpc/vpnconnection.go"},
	{Type: "WAF", Group: "SECURITY", Dimension: DimensionGlobal, CollectorPath: "collector/alicloud/collector/waf/waf.go"},
	{Type: "Yundun", Group: "SECURITY", Dimension: DimensionRegional, CollectorPath: "collector/alicloud/collector/yundun/yundun.go"},
}

func AllResourceSpecs() []ResourceSpec {
	specs := make([]ResourceSpec, len(collectorResourceCatalog))
	for i, spec := range collectorResourceCatalog {
		if spec.Normalized == "" {
			spec.Normalized = normalizeResourceType(spec.Type)
		}
		specs[i] = spec
	}
	return specs
}

func AllResourceTypes() []string {
	specs := AllResourceSpecs()
	types := make([]string, 0, len(specs))
	for _, spec := range specs {
		types = append(types, spec.Type)
	}
	return types
}

func ResourceSpecByType(resourceType string) (ResourceSpec, bool) {
	normalized := normalizeResourceType(resourceType)
	compact := compactResourceType(resourceType)
	for _, spec := range AllResourceSpecs() {
		if spec.Normalized == normalized || normalizeResourceType(spec.Type) == normalized || compactResourceType(spec.Type) == compact {
			return spec, true
		}
	}
	return ResourceSpec{}, false
}

func normalizeResourceType(resourceType string) string {
	resourceType = strings.TrimSpace(resourceType)
	var builder strings.Builder
	lastUnderscore := false
	var previous rune
	runes := []rune(resourceType)
	for index, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			next := rune(0)
			if index+1 < len(runes) {
				next = runes[index+1]
			}
			if builder.Len() > 0 && !lastUnderscore && shouldSplitUppercase(previous, next) {
				builder.WriteByte('_')
			}
			builder.WriteRune(r + ('a' - 'A'))
			lastUnderscore = false
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastUnderscore = false
		default:
			if builder.Len() > 0 && !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
		previous = r
	}
	return strings.Trim(builder.String(), "_")
}

func shouldSplitUppercase(previous rune, next rune) bool {
	if (previous >= 'a' && previous <= 'z') || (previous >= '0' && previous <= '9') {
		return true
	}
	return previous >= 'A' && previous <= 'Z' && next >= 'a' && next <= 'z'
}

func compactResourceType(resourceType string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(resourceType)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
