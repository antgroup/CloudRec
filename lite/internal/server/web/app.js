(function () {
  "use strict";

  const routes = {
    overview: "route.overview",
    risks: "route.risks",
    assets: "route.assets",
    relationships: "route.relationships",
    scans: "route.scans",
    rules: "route.rules",
    settings: "route.settings",
  };

  const routeInitials = {
    overview: { en: "O", zh: "总" },
    risks: { en: "R", zh: "险" },
    assets: { en: "A", zh: "资" },
    relationships: { en: "T", zh: "拓" },
    scans: { en: "S", zh: "扫" },
    rules: { en: "P", zh: "规" },
    settings: { en: "G", zh: "设" },
  };

  const languageKey = "cloudrec-lite-language";
  const fallbackLanguage = "en";

  const messages = {
    en: {
      "brand.lite": "Lite",
      "shell.primaryNavigation": "Primary navigation",
      "shell.eyebrow": "Security control plane",
      "shell.language": "Language",
      "route.overview": "Overview",
      "route.risks": "Risks",
      "route.assets": "Assets",
      "route.relationships": "Topology",
      "route.scans": "Scans",
      "route.rules": "Rules",
      "route.settings": "Settings",
      "filters.account": "Account",
      "filters.provider": "Provider",
      "filters.resource": "Resource Type",
      "filters.severity": "Severity",
      "filters.status": "Status",
      "filters.limit": "Limit",
      "filters.all": "all",
      "filters.accountPlaceholder": "all accounts",
      "filters.providerPlaceholder": "any",
      "filters.resourcePlaceholder": "all resource types",
      "actions.apply": "Apply",
      "actions.reset": "Reset",
      "status.checking": "Checking",
      "status.online": "Online",
      "status.issue": "Issue",
      "status.unknown": "Unknown",
      "status.updated": "Updated",
      "drawer.details": "Details",
      "drawer.selectRow": "Select a row",
      "drawer.close": "Close details",
    },
    zh: {
      "brand.lite": "轻量版",
      "shell.primaryNavigation": "主导航",
      "shell.eyebrow": "本地只读 CSPM",
      "shell.language": "语言",
      "route.overview": "总览",
      "route.risks": "风险",
      "route.assets": "资产",
      "route.relationships": "资产拓扑",
      "route.scans": "扫描",
      "route.rules": "规则",
      "route.settings": "设置",
      "filters.account": "账号",
      "filters.provider": "云厂商",
      "filters.resource": "资源类型",
      "filters.severity": "严重度",
      "filters.status": "状态",
      "filters.limit": "返回数量",
      "filters.all": "全部",
      "filters.accountPlaceholder": "全部账号",
      "filters.providerPlaceholder": "任意",
      "filters.resourcePlaceholder": "全部资源类型",
      "actions.apply": "应用",
      "actions.reset": "重置",
      "status.checking": "检查中",
      "status.online": "在线",
      "status.issue": "异常",
      "status.unknown": "未知",
      "status.updated": "已更新",
      "drawer.details": "详情",
      "drawer.selectRow": "选择一行",
      "drawer.close": "关闭详情",
    },
  };

  const zhPhrases = {
    "Local cloud posture": "本地云安全风险态势",
    "CloudRec's Protecting More": "CloudRec's Protecting More",
    "CloudRec Lite combines findings, inventory, scan deltas, and relationship context into a focused console that keeps noisy evidence close to the resource it affects.": "CloudRec Lite 是面向中小团队的轻量 CSPM 本地只读控制台，帮助快速发现云上风险、盘点资产，并把风险定位到受影响资源。",
    "Review open risks": "处理未修复风险",
    "Inspect inventory": "盘点资产",
    "Map relationships": "查看资产拓扑",
    "First Run Guide": "首次运行引导",
    "No scan data is stored yet. Run these commands locally to validate setup, scan, and reopen this console.": "当前还没有扫描数据。按下面四步在本地安全保存凭证、检查环境、扫描并启动页面。",
    "Credentials stay in your OS credential store or one-shot shell environment and are never shown in this page.": "凭证保存在系统凭证库或一次性 Shell 环境变量中，页面不会展示凭证值。",
    "1. Store Credentials": "1. 安全保存凭证",
    "2. Doctor": "2. 环境检查",
    "3. Scan": "3. 执行扫描",
    "4. Serve": "4. 打开页面",
    "read-only": "只读",
    "Runtime": "运行时",
    "Assets": "资产",
    "Inventory objects in scope": "当前纳管的云资产",
    "Open Risks": "未修复风险",
    "Findings still needing attention": "需要跟进的风险",
    "Relationships": "资产拓扑",
    "Topology": "资产拓扑",
    "Observed asset edges": "已发现的拓扑连线",
    "Rules": "规则",
    "Policy checks available": "可用检测规则",
    "Attention Queue": "待处理风险",
    "Latest open findings, normalized across old and new API shapes.": "汇总最新未修复风险，兼容新旧 Lite API 返回。",
    "shown": "已显示",
    "Severity Mix": "严重度分布",
    "Scan Delta": "资产变化",
    "Top Facets": "常用筛选项",
    "Recent Scans": "最近扫描",
    "Scan runs stored in the current database.": "当前数据库中保存的扫描记录。",
    "Started": "开始",
    "Finished": "结束",
    "Duration": "耗时",
    "Run": "扫描",
    "Coverage Snapshot": "规则覆盖概览",
    "Findings": "风险",
    "Shown": "当前页",
    "Current page rows": "当前页记录数",
    "Critical rows on this page": "当前页严重风险",
    "Results matching active filters": "匹配当前筛选的结果",
    "Critical": "严重",
    "Immediate response candidates": "建议优先处理",
    "High": "高危",
    "High-impact posture issues": "影响较高的云安全风险",
    "Open": "未修复",
    "Not yet resolved or suppressed": "尚未修复或忽略的风险",
    "Risk Register": "风险台账",
    "Click any row to open the finding drawer. Detail calls use /api/finding and fall back to list data.": "点击任意风险查看详情。详情优先读取 /api/finding，失败时使用列表数据。",
    "Remediation Context": "修复上下文",
    "Inventory rows returned": "当前返回资产",
    "Inventory rows matching filters": "匹配筛选的资产",
    "Resource Types": "资源类型",
    "Distinct services or asset families": "不同资源类型",
    "Providers": "云厂商",
    "Cloud providers represented": "已覆盖云厂商",
    "Regions": "地域",
    "Observed deployment regions": "发现资产所在地域",
    "Asset Inventory": "资产清单",
    "Click any row to call /api/asset, with fallback to the list response.": "点击任意资产查看详情。详情优先读取 /api/asset，失败时使用列表数据。",
    "Public Entry": "公网入口",
    "Internet-facing load balancers": "可从公网访问的负载均衡",
    "Backend ECS": "后端 ECS",
    "Compute nodes behind traffic entry": "入口流量后的计算节点",
    "Security Groups": "安全组",
    "Policy groups on backend ECS": "后端 ECS 绑定的策略组",
    "Open Policies": "开放策略",
    "Ingress rules allowing any source": "允许任意来源访问的入站规则",
    "Public Exposure": "公网暴露",
    "Public LB plus internet-facing data assets": "公网入口与公网可达数据资产",
    "Data Exposure": "数据暴露",
    "Public ACL, endpoint, or wide whitelist": "公开 ACL、公网端点或宽松白名单",
    "Credential Paths": "凭证路径",
    "Unrestricted active AK paths": "活跃 AK 可触达的数据或控制面路径",
    "Topology Edges": "拓扑连线",
    "Visible inferred relationships": "当前展示的拓扑连线",
    "Network Exposure Topology": "公网暴露拓扑",
    "Shows Internet to public load balancer, listener, backend ECS, and security-group ingress policy. Click any collected cloud resource node to inspect details.": "展示 Internet 到公网负载均衡、监听、后端 ECS 和安全组入站策略的链路。点击已采集的云资源节点可查看详情。",
    "Backend authoritative traffic paths": "后端权威流量路径",
    "Traffic Exposure Paths": "流量暴露路径",
    "Public SLB / ALB / NLB to ECS to security-group policy. Built from load balancer properties plus ECS security-group relationships.": "从公网 SLB/ALB/NLB 到 ECS，再到安全组策略；基于负载均衡属性和 ECS 安全组关系拼接。",
    "Open path details": "展开链路详情",
    "Collapse path details": "收起链路详情",
    "Open asset details": "查看资产详情",
    "Click a node to open asset details. Expand a path to inspect listeners, backends, and security-group policies.": "点击节点查看资产详情；展开链路可检查监听、后端和安全组策略。",
    "Internet": "公网",
    "Listener": "监听",
    "Security Group": "安全组",
    "Ingress Policy": "入站策略",
    "No backend ECS captured": "未采集后端 ECS",
    "No linked security group": "未关联安全组",
    "Inbound restricted": "入站受限",
    "Internet open": "公网开放",
    "No load balancer paths available.": "暂无可展示的负载均衡链路。",
    "Search exposed paths": "搜索暴露链路",
    "Port": "端口",
    "Any port": "任意端口",
    "Open policy": "开放策略",
    "Any policy": "任意策略",
    "Wide open only": "仅开放策略",
    "Restricted only": "仅受限策略",
    "Exposure & Permission Paths": "暴露与权限路径",
    "Data exposure and AK permission paths are grouped in one balanced area so long evidence does not distort the page rhythm.": "将数据暴露与 AK 权限路径放在同一个平衡区域，避免长短不一的证据卡片破坏页面节奏。",
    "data exposure": "数据暴露",
    "AK paths": "AK 路径",
    "Data Exposure Paths": "数据暴露路径",
    "OSS and SLS public access is determined by resource policy. Databases and caches separate public endpoint exposure from broad access lists.": "OSS 和 SLS 公网访问通过资源策略判断；数据库和缓存类服务会区分公网端点与宽松访问白名单。",
    "No data exposure detected from current asset properties.": "当前资产属性中未发现数据暴露。",
    "Bucket has public ACL but BlockPublicAccess is enabled, so it is not counted as effective public exposure.": "Bucket 配置了公开 ACL，但已启用 BlockPublicAccess，因此不计为实际公网暴露。",
    "Public endpoint exists; whitelist controls who can reach it.": "已发现公网端点，访问白名单决定可连接来源。",
    "Whitelist is broad, but no public endpoint was found in collected properties.": "白名单范围较宽，但当前采集属性中未发现公网端点。",
    "AK Permission Paths": "AK 权限路径",
    "Grouped by RAM identity and service, then split into data-plane access and control-plane change risk. Source restriction unknown is shown separately from confirmed unrestricted paths.": "按 RAM 身份和服务聚合，并区分数据面访问与控制面变更风险。来源限制未知会和已确认未限制分开展示。",
    "Data-plane credential access": "数据面凭证访问",
    "AK can call data APIs such as OSS or SLS directly when policy and target resource match.": "当权限策略与目标资源匹配时，AK 可直接调用 OSS、SLS 等数据面 API。",
    "Control-plane credential risk": "控制面凭证风险",
    "AK can view or change database/cache exposure, but cannot directly read data without service credentials.": "AK 可查看或修改数据库、缓存等服务的暴露配置，但不能绕过服务账号直接读取数据。",
    "Credential Access Paths": "AK 权限路径",
    "OSS and SLS can be reached through data-plane APIs when an unrestricted active AK has data permissions. Database and cache services are shown as management-plane paths because AK can change exposure but cannot directly read data without database credentials.": "当活跃 AK 拥有数据权限且调用来源未限制时，OSS 和 SLS 可通过数据面 API 访问；数据库和缓存服务展示为控制面路径，因为 AK 可修改暴露配置，但不能绕过数据库账号直接读取数据。",
    "No unrestricted active access-key path detected.": "未发现未限制来源的活跃 AK 路径。",
    "public endpoint": "公网端点",
    "internet-facing": "公网可达",
    "public ACL": "公开 ACL",
    "public policy": "公共策略",
    "public policy write": "公共策略写权限",
    "wide whitelist": "宽松白名单",
    "public read": "公网读",
    "public write": "公网写",
    "read/write": "读写",
    "control plane": "控制面",
    "data-plane access": "数据面访问",
    "management-plane change": "控制面变更",
    "management-plane visibility": "控制面可见",
    "source unrestricted": "调用来源未限制",
    "source restricted": "调用来源已限制",
    "source acl not collected": "来源限制未采集",
    "Source Restriction": "调用来源限制",
    "AK Source ACL": "调用来源限制",
    "not collected": "来源未知",
    "unrestricted": "未限制",
    "restricted": "已限制",
    "confirmed": "已确认",
    "needs verification": "需补采确认",
    "Policy documents": "策略文档",
    "Source conditions": "来源条件",
    "No source restriction condition was collected for this credential path.": "当前凭证路径未采集到来源限制条件。",
    "PolicyDocument was not collected, so this path is treated as source-unknown rather than proven unrestricted.": "未采集到 PolicyDocument，因此该路径是“来源限制未知”，不是已证明完全无限制。",
    "can read/write data": "可读写数据",
    "can change exposure": "可改变暴露面",
    "can inspect configuration": "可查看配置",
    "Permission": "权限",
    "Affected targets": "影响目标",
    "Policy": "策略",
    "Resource scope": "资源范围",
    "identity": "身份",
    "target": "目标",
    "active AK": "活跃 AK",
    "inactive AK": "停用 AK",
    "policies": "策略",
    "full access": "完全权限",
    "read access": "只读权限",
    "manage access": "管理权限",
    "Entry": "入口",
    "Compute": "计算",
    "Policy": "策略",
    "Public": "公网",
    "Private": "私网",
    "Backend missing": "未采集后端",
    "No security group link": "缺少安全组关系",
    "ACL off": "ACL 未开启",
    "ACL on": "ACL 已开启",
    "listeners": "监听",
    "backends": "后端",
    "groups": "安全组",
    "port": "端口",
    "weight": "权重",
    "rules": "规则",
    "wide open": "公网开放",
    "global": "全局",
    "No backend captured": "未采集到后端",
    "No security group policies linked": "未关联到安全组策略",
    "Complete Topology Preview": "完整资产拓扑",
    "Layered preview of collected assets and inferred edges. Large lanes are sampled to keep the graph readable.": "按层展示已采集资产和推导关系；资产过多时会抽样展示，保证图可读。",
    "Collected Assets": "采集资产",
    "Inferred Edges": "推导关系",
    "Visible Nodes": "展示节点",
    "Sampled lanes": "抽样分层",
    "Network & Policy": "网络与策略",
    "Data": "数据",
    "Identity": "身份",
    "Other": "其他",
    "Relationship Evidence": "拓扑证据",
    "Raw ECS to security-group edges from /api/relationships.": "来自 /api/relationships 的 ECS 到安全组原始关系。",
    "Path Coverage": "路径覆盖",
    "Load balancers without backend data": "缺少后端数据的负载均衡",
    "Backend ECS without security-group edge": "缺少安全组关系的后端 ECS",
    "Listeners without ACL": "未开启 ACL 的监听",
    "Data assets checked": "已检查数据资产",
    "Internet-facing data assets": "公网可达数据资产",
    "Data assets with broad ACL": "存在宽松 ACL 的数据资产",
    "RAM users with unrestricted active AK paths": "未限制来源 AK 路径的 RAM 用户",
    "Raw ECS-security group edges": "原始 ECS-安全组关系",
    "Raw Relationship Map": "原始拓扑图",
    "Relationship Edges": "拓扑连线列表",
    "List data comes from /api/relationships. Graph data comes from /api/graph or is derived locally.": "列表读取 /api/relationships，拓扑图读取 /api/graph；接口不可用时会在本地生成简图。",
    "Relationship Map": "资产拓扑图",
    "Edges matching active filters": "匹配筛选的连线数",
    "Graph Nodes": "图谱节点",
    "Unique resources in graph": "拓扑图中的资产数",
    "Edge Types": "连线类型",
    "Relationship classes": "不同连线类型",
    "Targets": "目标",
    "Distinct downstream resources": "关联到的目标资源",
    "Runs": "扫描次数",
    "Scan runs returned": "当前返回扫描任务",
    "Scan runs matching filters": "匹配筛选的扫描任务",
    "Succeeded": "成功",
    "Completed successfully": "已完成",
    "Failed": "失败",
    "Runs needing inspection": "需要排查的任务",
    "Running": "运行中",
    "Currently in progress": "正在扫描",
    "Scan Runs": "扫描任务",
    "Compact execution history from /api/scan-runs.": "展示 /api/scan-runs 返回的最近扫描记录。",
    "Loaded rule definitions": "已加载检测规则",
    "Covered asset families": "已覆盖资源类型",
    "With Examples": "含示例",
    "Rules with input examples": "包含示例输入的规则",
    "Missing Refs": "缺失数据",
    "Coverage references to resolve": "规则所需但暂缺的数据",
    "Rule Catalog": "规则目录",
    "Uses /api/rules when available. Empty state is expected on older Lite servers.": "优先读取 /api/rules；旧版 Lite 服务可能不会返回规则目录。",
    "Coverage": "覆盖情况",
    "Active Filters": "当前筛选",
    "Facet Cache": "筛选项缓存",
    "Runbook": "运行手册",
    "The Lite console is intentionally read-only. It never edits accounts, waivers, rules, or cloud resources.": "Lite 控制台刻意保持只读，不会编辑账号、豁免、规则或云资源。",
    "Safety Notes": "安全提示",
    "API Coverage": "API 覆盖",
    "The UI calls the new Lite Web APIs and records whether a fallback was needed for older servers.": "页面会调用 Lite Web API，并标记旧版服务是否使用了兼容回退。",
    "No detail fields.": "暂无详情字段。",
    "Raw JSON": "原始 JSON",
    "Loading detail...": "正在加载详情...",
    "Unable to load detail": "无法加载详情",
    "No findings match the active filters.": "没有匹配当前筛选的风险。",
    "No assets match the active filters.": "没有匹配当前筛选的资产。",
    "No relationships match the active filters.": "没有匹配当前筛选的拓扑连线。",
    "Scan Quality": "扫描质量",
    "Can users trust this run? Collection failures and rule coverage make that explicit.": "用户是否可以信任本次扫描？采集失败和规则覆盖会在这里明确展示。",
    "Collection Health": "采集健康度",
    "Rule Coverage": "规则评估覆盖率",
    "Rule Quality": "规则质量",
    "Official Reviewed": "官方审计",
    "Field Verified": "字段验证",
    "Missing Sample Refs": "缺失样本字段",
    "Missing Data Refs": "缺失数据引用",
    "Missing Remediation": "缺失修复建议",
    "Collection Failures": "采集失败",
    "Failure Categories": "失败分类",
    "Failed Resource Types": "失败资源类型",
    "Resource Type Drilldown": "资源类型明细",
    "Trust blockers grouped by product. Fix these before treating a clean result as complete.": "按产品聚合扫描可信度阻断项。修复这些问题后，空结果才更可信。",
    "No resource-type blockers.": "暂无资源类型阻断项。",
    "Evaluated Rules": "已评估规则",
    "Latest scan": "最近扫描",
    "complete": "完整",
    "partial": "部分成功",
    "failed": "失败",
    "empty": "无数据",
    "unknown": "未知",
    "verified": "已验证",
    "needs_review": "待审计",
    "missing_fields": "字段缺失",
    "missing_remediation": "缺修复建议",
    "needs_logic_change": "需调整逻辑",
    "blocked": "已阻塞",
    "rules_unavailable": "规则不可用",
    "missing_samples": "缺样本",
    "no_input_refs": "无输入依赖",
    "No scan runs match the active filters.": "没有匹配当前筛选的扫描任务。",
    "No rule catalog API response yet.": "暂未获取到规则目录。",
    "Coverage API is not available yet, or returned no rules.": "暂未获取到规则覆盖数据。",
    "No graph nodes available.": "暂无图谱节点。",
    "No facet values returned yet.": "暂未获取到筛选项。",
    "No values.": "暂无数据。",
    "No recent scan runs.": "暂无最近扫描任务。",
    "Rules with no missing data references": "数据依赖完整的规则",
    "Added": "新增",
    "Seen": "已发现",
    "Types": "类型",
    "Examples": "示例",
    "Missing": "缺失",
    "Accounts": "账号",
    "Resources": "资源",
    "API": "接口",
    "Database": "数据库",
    "assets": "个资产",
    "edges": "条连线",
    "rules": "条规则",
    "Safety": "安全",
    "Severity": "严重度",
    "Status": "状态",
    "Rule": "规则",
    "Resource": "资源",
    "Asset": "资产",
    "Title": "标题",
    "Last Seen": "最近发现",
    "Type": "类型",
    "Name": "名称",
    "Provider": "云厂商",
    "Region": "地域",
    "Resource ID": "资源 ID",
    "Source Type": "源资源类型",
    "Source": "源",
    "Target": "目标",
    "Started": "开始时间",
    "Finished": "结束时间",
    "Native": "原生采集",
    "yes": "是",
    "no": "否",
    "Relationship": "拓扑关系",
    "Updated": "更新时间",
    "Not configured": "未配置",
    "No write actions exposed in Web v1": "Web v1 不暴露写操作",
    "Will be called by the related page or drawer.": "会在相关页面或详情抽屉中调用。",
    "Search": "搜索",
    "Sort": "排序",
    "Newest first": "最新优先",
    "Oldest first": "最旧优先",
    "Highest severity": "严重度最高",
    "Lowest severity": "严重度最低",
    "Rule ID": "规则 ID",
    "Title A-Z": "标题 A-Z",
    "Name A-Z": "名称 A-Z",
    "Type A-Z": "类型 A-Z",
    "Region A-Z": "地域 A-Z",
    "Status A-Z": "状态 A-Z",
    "Provider A-Z": "云厂商 A-Z",
    "Started newest": "最近开始",
    "Started oldest": "最早开始",
    "Resource ID A-Z": "资源 ID A-Z",
    "Relationship type": "关系类型",
    "Source A-Z": "源资源 A-Z",
    "Target A-Z": "目标资源 A-Z",
    "Search risks": "搜索风险",
    "Search assets": "搜索资产",
    "Search scan runs": "搜索扫描任务",
    "Search rules": "搜索规则",
    "Showing": "显示",
    "of": "共",
    "Previous": "上一页",
    "Next": "下一页",
  };

  const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
  const findingStatuses = new Set(["open", "resolved", "suppressed"]);
  const scanStatuses = new Set(["running", "succeeded", "failed"]);
  const resourceTypeGroups = [
    { key: "compute", en: "Compute", zh: "计算", values: ["ECS"] },
    { key: "network", en: "Network", zh: "网络", values: ["SLB", "ALB", "NLB", "Security Group"] },
    { key: "data", en: "Data", zh: "数据", values: ["OSS", "SLS", "RDS", "Redis", "MongoDB", "PolarDB", "ClickHouse", "Lindorm", "HBase", "Elasticsearch", "Kafka", "RocketMQ"] },
    { key: "identity", en: "Identity", zh: "身份", values: ["RAM User", "RAM Role", "Account"] },
    { key: "other", en: "Other", zh: "其他", values: [] },
  ];
  const endpoints = [
    "/api/dashboard",
    "/api/facets",
    "/api/findings",
    "/api/finding",
    "/api/assets",
    "/api/asset",
    "/api/relationships",
    "/api/risk-paths",
    "/api/graph",
    "/api/scan-runs",
    "/api/scan-quality",
    "/api/rules",
    "/api/rules/coverage",
    "/api/runtime",
  ];

  const state = {
    route: "overview",
    language: normalizeLanguage(localStorage.getItem(languageKey) || navigator.language),
    filters: {
      account_id: "",
      provider: "",
      resource_type: "",
      severity: "",
      status: "",
      limit: "50",
    },
    pages: {
      risks: { offset: 0, q: "", sort: "" },
      assets: { offset: 0, q: "", sort: "" },
      scans: { offset: 0, q: "", sort: "" },
      rules: { offset: 0, q: "", sort: "" },
    },
    detailIndex: new Map(),
    apiHealth: new Map(),
    dashboard: null,
    facets: null,
    runtime: null,
  };

  const el = {
    view: document.getElementById("view"),
    title: document.getElementById("pageTitle"),
    status: document.getElementById("appStatus"),
    nav: document.getElementById("navList"),
    form: document.getElementById("filterForm"),
    healthDot: document.getElementById("healthDot"),
    healthLabel: document.getElementById("healthLabel"),
    drawer: document.getElementById("detailDrawer"),
    drawerBackdrop: document.getElementById("drawerBackdrop"),
    drawerClose: document.getElementById("drawerClose"),
    drawerKicker: document.getElementById("drawerKicker"),
    drawerTitle: document.getElementById("drawerTitle"),
    drawerBody: document.getElementById("drawerBody"),
    resetFilters: document.getElementById("resetFilters"),
    languageButtons: Array.from(document.querySelectorAll("[data-lang]")),
    inputs: {
      account_id: document.getElementById("filterAccount"),
      provider: document.getElementById("filterProvider"),
      resource_type: document.getElementById("filterResourceType"),
      severity: document.getElementById("filterSeverity"),
      status: document.getElementById("filterStatus"),
      limit: document.getElementById("filterLimit"),
    },
  };

  const api = {
    dashboard: async () => {
      const body = await firstJSON([
        { path: "/api/dashboard", params: baseParams() },
        { path: "/api/summary", params: pickParams(["account_id"]) },
      ]);
      return normalizeDashboard(body);
    },

    facets: async (overrides) => {
      const params = compact({ ...baseParams(), ...overrides });
      const body = await fetchJSON("/api/facets", params, { optional: true });
      if (body) {
        return normalizeFacets(body);
      }

      const [findings, assets, relationships, scans] = await Promise.all([
        api.findings({ ...overrides, limit: 500 }).catch(() => []),
        api.assets({ ...overrides, limit: 500 }).catch(() => []),
        api.relationships({ ...overrides, limit: 500 }).catch(() => []),
        api.scanRuns({ limit: 100 }).catch(() => []),
      ]);
      return deriveFacets({ findings, assets, relationships, scans });
    },

    findings: async (overrides) => {
      return (await api.findingsPage(overrides)).items;
    },

    findingsPage: async (overrides) => {
      const body = await fetchJSON("/api/findings", findingsParams(overrides));
      return normalizeCollection(body, ["findings", "items", "results", "data"], normalizeFinding);
    },

    finding: async (item) => {
      const id = item.id || item.finding_id;
      const detail = await fetchJSON("/api/finding", compact({
        id,
        finding_id: id,
        rule_id: item.rule_id,
        asset_id: item.asset_id,
        account_id: item.account_id,
      }), { optional: true });
      const normalized = firstRecord(detail, ["finding", "item", "data", "result"]);
      if (normalized) {
        return normalizeFinding(normalized);
      }

      const findings = await api.findings({ limit: 1000, status: "", severity: "" }).catch(() => []);
      return findings.find((finding) => sameID(finding, item)) || item;
    },

    assets: async (overrides) => {
      return (await api.assetsPage(overrides)).items;
    },

    assetsPage: async (overrides) => {
      const body = await fetchJSON("/api/assets", assetParams(overrides));
      return normalizeCollection(body, ["assets", "items", "results", "data"], normalizeAsset);
    },

    asset: async (item) => {
      const id = item.id || item.asset_id;
      const detail = await fetchJSON("/api/asset", compact({
        id,
        asset_id: id,
        resource_id: item.resource_id,
        account_id: item.account_id,
        provider: item.provider,
      }), { optional: true });
      const normalized = firstRecord(detail, ["asset", "item", "data", "result"]);
      if (normalized) {
        return normalizeAsset({
          ...normalized,
          product_summary: valueFrom(normalized, ["product_summary", "productSummary"], valueFrom(detail, ["product_summary", "productSummary"], null)),
        });
      }

      const assets = await api.assets({
        limit: 1000,
        resource_type: item.resource_type || "",
        resource_id: item.resource_id || "",
      }).catch(() => []);
      return assets.find((asset) => sameID(asset, item) || asset.resource_id === item.resource_id) || item;
    },

    relationships: async (overrides) => {
      return (await api.relationshipsPage(overrides)).items;
    },

    relationshipsPage: async (overrides) => {
      const body = await fetchJSON("/api/relationships", relationshipParams(overrides));
      return normalizeCollection(body, ["relationships", "edges", "items", "results", "data"], normalizeRelationship);
    },

    riskPaths: async (overrides) => {
      const body = await fetchJSON("/api/risk-paths", compact({ ...baseParams(), ...overrides }), { optional: true });
      return normalizeRiskPaths(body);
    },

    graph: async (overrides) => {
      const body = await fetchJSON("/api/graph", relationshipParams(overrides), { optional: true });
      if (body) {
        return normalizeGraph(body);
      }
      const relationships = await api.relationships(overrides).catch(() => []);
      return graphFromRelationships(relationships);
    },

    scanRuns: async (overrides) => {
      return (await api.scanRunsPage(overrides)).items;
    },

    scanRunsPage: async (overrides) => {
      const body = await fetchJSON("/api/scan-runs", scanParams(overrides));
      return normalizeCollection(body, ["scan_runs", "scanRuns", "runs", "items", "results", "data"], normalizeScanRun);
    },

    scanQuality: async (overrides) => {
      const body = await fetchJSON("/api/scan-quality", scanParams(overrides), { optional: true });
      return normalizeScanQuality(body);
    },

    rules: async (overrides) => {
      return (await api.rulesPage(overrides)).items;
    },

    rulesPage: async (overrides) => {
      const body = await fetchJSON("/api/rules", compact({ ...baseParams(), ...overrides }), { optional: true });
      return normalizeCollection(body, ["rules", "items", "results", "data"], normalizeRule);
    },

    coverage: async () => {
      const body = await fetchJSON("/api/rules/coverage", pickParams(["provider", "resource_type"]), { optional: true });
      return normalizeCoverage(body);
    },

    runtime: async () => {
      const body = await firstJSON([
        { path: "/api/runtime", params: {} },
        { path: "/healthz", params: {} },
      ], { optional: true });
      return normalizeRuntime(body);
    },
  };

  function normalizeLanguage(value) {
    const language = String(value || "").toLowerCase();
    return language.startsWith("zh") ? "zh" : fallbackLanguage;
  }

  function t(key, fallback) {
    return (messages[state.language] && messages[state.language][key]) ||
      (messages[fallbackLanguage] && messages[fallbackLanguage][key]) ||
      fallback ||
      key;
  }

  function routeLabel(route) {
    return t(routes[route], route);
  }

  function routeInitial(route) {
    const initials = routeInitials[route] || {};
    return initials[state.language] || initials[fallbackLanguage] || route.slice(0, 1).toUpperCase();
  }

  function boot() {
    syncFiltersFromDOM();
    bindEvents();
    translateStaticShell();
    hydrateFilterFacets();
    refreshRuntime();
    renderRoute();
  }

  function bindEvents() {
    window.addEventListener("hashchange", renderRoute);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeDrawer();
      }
    });

    el.form.addEventListener("submit", (event) => {
      event.preventDefault();
      syncFiltersFromDOM();
      resetPageOffsets();
      renderRoute();
    });

    for (const input of Object.values(el.inputs)) {
      input.addEventListener("change", () => {
        syncFiltersFromDOM();
      });
    }

    el.resetFilters.addEventListener("click", () => {
      state.filters = {
        account_id: "",
        provider: "",
        resource_type: "",
        severity: "",
        status: "",
        limit: "50",
      };
      Object.keys(state.pages).forEach((route) => {
        state.pages[route] = { offset: 0, q: "", sort: "" };
      });
      syncDOMFromFilters();
      renderRoute();
    });

    for (const button of el.languageButtons) {
      button.addEventListener("click", () => {
        const nextLanguage = normalizeLanguage(button.dataset.lang);
        if (nextLanguage === state.language) {
          return;
        }
        state.language = nextLanguage;
        localStorage.setItem(languageKey, state.language);
        translateStaticShell();
        applyRuntimeHealth(state.runtime || {});
        renderRoute();
      });
    }

    el.view.addEventListener("click", (event) => {
      const pageButton = event.target.closest("[data-page-action]");
      if (pageButton) {
        const route = pageButton.dataset.pageRoute || state.route;
        const page = pageState(route);
        const limit = pageLimit();
        if (pageButton.dataset.pageAction === "prev") {
          page.offset = Math.max(0, page.offset - limit);
        } else if (pageButton.dataset.pageAction === "next") {
          page.offset += limit;
        }
        renderRoute();
        return;
      }
      const row = event.target.closest("[data-key]");
      if (!row) {
        return;
      }
      const record = state.detailIndex.get(row.dataset.key);
      if (record) {
        openDrawer(record.kind, record.item);
      }
    });
    el.view.addEventListener("change", (event) => {
      const field = event.target.closest("[data-page-field]");
      if (!field) {
        return;
      }
      const route = field.dataset.pageRoute || state.route;
      const page = pageState(route);
      page[field.dataset.pageField] = String(field.value || "").trim();
      page.offset = 0;
      renderRoute();
    });
    el.view.addEventListener("keydown", (event) => {
      const field = event.target.closest("[data-page-field]");
      if (!field || event.key !== "Enter") {
        return;
      }
      event.preventDefault();
      const route = field.dataset.pageRoute || state.route;
      const page = pageState(route);
      page[field.dataset.pageField] = String(field.value || "").trim();
      page.offset = 0;
      renderRoute();
    });
    el.view.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      const node = event.target.closest("[data-key]");
      if (!node) {
        return;
      }
      event.preventDefault();
      const record = state.detailIndex.get(node.dataset.key);
      if (record) {
        openDrawer(record.kind, record.item);
      }
    });

    el.drawerClose.addEventListener("click", closeDrawer);
    el.drawerBackdrop.addEventListener("click", closeDrawer);
  }

  async function renderRoute() {
    state.route = routeFromHash();
    state.detailIndex.clear();
    el.title.textContent = routeLabel(state.route);
    setActiveNav();
    setStatus("");
    showLoading();

    try {
      if (state.route === "overview") {
        await renderOverview();
      } else if (state.route === "risks") {
        await renderRisks();
      } else if (state.route === "assets") {
        await renderAssets();
      } else if (state.route === "relationships") {
        await renderRelationships();
      } else if (state.route === "scans") {
        await renderScans();
      } else if (state.route === "rules") {
        await renderRules();
      } else if (state.route === "settings") {
        await renderSettings();
      }
      localizeRenderedText(el.view);
      setStatus(t("status.updated") + " " + new Date().toLocaleTimeString());
    } catch (error) {
      renderError(error);
    }
  }

  async function renderOverview() {
    const [dashboard, facets, runtime, findings, scans, coverage] = await Promise.all([
      api.dashboard(),
      api.facets(),
      api.runtime(),
      api.findings({ limit: 6, status: "open" }).catch(() => []),
      api.scanRuns({ limit: 4, status: "" }).catch(() => []),
      api.coverage().catch(() => normalizeCoverage(null)),
    ]);

    state.dashboard = dashboard;
    state.facets = facets;
    state.runtime = runtime;
    applyRuntimeHealth(runtime);

    el.view.innerHTML = `
      <section class="hero">
        <article class="hero-card">
          <p class="eyebrow">Local cloud posture</p>
          <h2 class="hero-title">CloudRec's Protecting More</h2>
          <p class="hero-copy">CloudRec Lite combines findings, inventory, scan deltas, and relationship context into a focused console that keeps noisy evidence close to the resource it affects.</p>
          <div class="hero-actions">
            <a href="#/risks">Review open risks</a>
            <a href="#/assets">Inspect inventory</a>
            <a href="#/topology">Map relationships</a>
          </div>
        </article>
        <aside class="panel">
          <h2>Runtime</h2>
          ${runtimePanel(runtime)}
        </aside>
      </section>

      ${firstRunPanel(runtime, dashboard, scans)}

      ${metricCards([
        ["Assets", dashboard.assetCount, "Inventory objects in scope", ""],
        ["Open Risks", dashboard.openFindingCount, "Findings still needing attention", "danger"],
        ["Topology", dashboard.relationshipCount, "Observed asset edges", ""],
        ["Rules", coverage.totalRules || dashboard.ruleCount || 0, "Policy checks available", "warn"],
      ])}

      <section class="content-grid">
        <article class="table-card">
          <div class="card-head">
            <div>
              <h2>Attention Queue</h2>
              <p>Latest open findings, normalized across old and new API shapes.</p>
            </div>
            <span class="chip open">${number(findings.length)} ${escapeHTML(state.language === "zh" ? "已显示" : "shown")}</span>
          </div>
          ${findingsTable(findings)}
        </article>

        <aside class="panel">
          <h2>Severity Mix</h2>
          ${severityBars(dashboard.severityCounts)}
          <h2>Scan Delta</h2>
          ${deltaGrid(dashboard.scanDelta)}
          <h2>Top Facets</h2>
          ${facetChips(facets)}
        </aside>
      </section>

      <section class="content-grid equal">
        <article class="panel">
          <h2>Recent Scans</h2>
          ${scanSummary(scans)}
        </article>
        <article class="panel">
          <h2>Coverage Snapshot</h2>
          ${coverageSummary(coverage)}
        </article>
      </section>
    `;
  }

  async function renderRisks() {
    const page = await api.findingsPage(pageRequest("risks"));
    const findings = page.items;
    const counts = countBy(findings, "severity");

    el.view.innerHTML = `
      ${metricCards([
        ["Findings", page.total, "Results matching active filters", ""],
        ["Shown", findings.length, "Current page rows", ""],
        ["Critical", counts.critical || 0, "Critical rows on this page", "danger"],
        ["Open", findings.filter((item) => item.status === "open").length, "Not yet resolved or suppressed", ""],
      ])}
      <section class="table-card">
        <div class="card-head">
          <div>
            <h2>Risk Register</h2>
            <p>Click any row to open the finding drawer. Detail calls use /api/finding and fall back to list data.</p>
          </div>
          <div class="chips">${severityOrder.map((severity) => severityChip(severity, counts[severity] || 0)).join("")}</div>
        </div>
        ${listToolbar("risks", "Search risks", riskSortOptions())}
        ${findingsTable(findings)}
        ${paginationControls("risks", page)}
      </section>
    `;
  }

  async function renderAssets() {
    const page = await api.assetsPage(pageRequest("assets"));
    const assets = page.items;
    const typeCounts = countBy(assets, "resource_type");
    const providerCounts = countBy(assets, "provider");

    el.view.innerHTML = `
      ${metricCards([
        ["Assets", page.total, "Inventory rows matching filters", ""],
        ["Shown", assets.length, "Current page rows", ""],
        ["Resource Types", Object.keys(typeCounts).length, "Distinct services or asset families", ""],
        ["Regions", Object.keys(countBy(assets, "region")).length, "Observed deployment regions", "warn"],
      ])}
      <section class="content-grid">
        <article class="table-card">
          <div class="card-head">
            <div>
              <h2>Asset Inventory</h2>
              <p>Click any row to call /api/asset, with fallback to the list response.</p>
            </div>
            <span class="chip">${number(page.total)} ${escapeHTML(state.language === "zh" ? "个资产" : "assets")}</span>
          </div>
          ${listToolbar("assets", "Search assets", assetSortOptions())}
          ${assetsTable(assets)}
          ${paginationControls("assets", page)}
        </article>
        <aside class="panel">
          <h2>Resource Types</h2>
          ${keyValueChips(typeCounts)}
          <h2>Providers</h2>
          ${keyValueChips(providerCounts)}
        </aside>
      </section>
    `;
  }

  async function renderRelationships() {
    const trafficPage = pageState("relationships");
    const trafficLimit = 6;
    const [relationships, graph, assets, riskPaths, trafficRiskPaths] = await Promise.all([
      api.relationships({ resource_type: "", limit: 1000 }),
      api.graph({ resource_type: "", limit: 1000 }),
      api.assets({ resource_type: "", limit: 1000 }),
      api.riskPaths({ resource_type: "", limit: 1000 }).catch(() => normalizeRiskPaths(null)),
      api.riskPaths({
        resource_type: "",
        path_type: "public_traffic_exposure",
        q: trafficPage.q || "",
        port: trafficPage.port || "",
        open_policy: trafficPage.open_policy || "",
        offset: trafficPage.offset || 0,
        limit: trafficLimit,
      }).catch(() => normalizeRiskPaths(null)),
    ]);
    const exposure = buildExposureModel(assets, relationships);
    const dataExposure = buildDataExposureModel(assets);
    const identityExposure = buildIdentityExposureModel(assets, dataExposure);
    const topology = buildTopologyModel(assets, relationships, exposure, dataExposure, identityExposure);
    const pathSummary = riskPaths.summary || {};
    const backendDataExposureCount = numberValue(pathSummary.anonymousPublicDataAccess) + numberValue(pathSummary.directNetworkExposure) + numberValue(pathSummary.broadNetworkACL);
    const backendCredentialPathCount = numberValue(pathSummary.credentialDataAccess) + numberValue(pathSummary.credentialControlPlaneExposure);
    const credentialGroups = riskPaths.available
      ? (riskPaths.groups || []).filter((group) => group.pathType === "credential_data_access" || group.pathType === "credential_control_plane_exposure")
      : [];
    const dataExposureCount = riskPaths.available ? backendDataExposureCount : dataExposure.exposedCount;
    const credentialPathCount = riskPaths.available ? (credentialGroups.length || backendCredentialPathCount) : identityExposure.unrestrictedRiskCount;
    const publicDataExposureCount = riskPaths.available
      ? numberValue(pathSummary.anonymousPublicDataAccess) + numberValue(pathSummary.directNetworkExposure)
      : dataExposure.internetFacingCount;
    const trafficExposure = trafficRiskPaths.available
      ? exposureFromTrafficPaths(trafficRiskPaths.trafficPaths)
      : exposure;
    const trafficTotal = trafficRiskPaths.available ? trafficRiskPaths.trafficTotal : trafficExposure.paths.length;
    const trafficPageInfo = {
      count: trafficExposure.paths.length,
      total: trafficTotal,
      offset: trafficPage.offset || 0,
      limit: trafficLimit,
    };

    el.view.innerHTML = `
      ${metricCards([
        ["Public Exposure", trafficExposure.publicEntryCount + publicDataExposureCount, "Public LB plus internet-facing data assets", trafficExposure.publicEntryCount + publicDataExposureCount ? "warn" : ""],
        ["Data Exposure", dataExposureCount, "Public ACL, endpoint, or wide whitelist", dataExposureCount ? "danger" : ""],
        ["Credential Paths", credentialPathCount, "Unrestricted active AK paths", backendCredentialPathCount ? "danger" : ""],
        ["Topology Edges", topology.edges.length, "Visible inferred relationships", ""],
      ])}
      <section class="panel relationship-paths">
        <div class="card-head">
          <div>
            <h2>Network Exposure Topology</h2>
            <p>Shows Internet to public load balancer, listener, backend ECS, and security-group ingress policy. Click any collected cloud resource node to inspect details.</p>
          </div>
          <span class="chip">${number(trafficTotal)} ${escapeHTML(state.language === "zh" ? "条链路" : "paths")}</span>
        </div>
        ${trafficPathToolbar()}
        ${networkExposureTopology(trafficExposure)}
        ${paginationControls("relationships", trafficPageInfo)}
      </section>
      <section class="panel exposure-balance-panel">
        <div class="card-head compact-head">
          <div>
            <h2>Exposure & Permission Paths</h2>
            <p>Data exposure and AK permission paths are grouped in one balanced area so long evidence does not distort the page rhythm.</p>
          </div>
          <div class="chips">
            ${chip(state.language === "zh" ? "数据暴露" : "data exposure", dataExposureCount)}
            ${chip(state.language === "zh" ? "AK 路径" : "AK paths", credentialPathCount)}
          </div>
        </div>
        <div class="exposure-balance-grid">
          <article class="exposure-balance-column">
            <div class="exposure-column-head">
              <div>
                <h3>Data Exposure Paths</h3>
                <p>OSS and SLS public access is determined by resource policy. Databases and caches separate public endpoint exposure from broad access lists.</p>
              </div>
              <span class="chip">${number(dataExposureCount)} ${escapeHTML(state.language === "zh" ? "个暴露项" : "exposures")}</span>
            </div>
            <div class="exposure-column-body">
              ${riskPathPanel(riskPaths, ["anonymous_public_data_access", "direct_network_exposure", "broad_network_acl"], () => dataExposurePanel(dataExposure), "No data exposure detected from current asset properties.")}
            </div>
          </article>
          <article class="exposure-balance-column">
            <div class="exposure-column-head">
              <div>
                <h3>AK Permission Paths</h3>
                <p>Grouped by RAM identity and service, then split into data-plane access and control-plane change risk. Source restriction unknown is shown separately from confirmed unrestricted paths.</p>
              </div>
              <span class="chip">${number(backendCredentialPathCount)} ${escapeHTML(state.language === "zh" ? "个影响目标" : "affected targets")}</span>
            </div>
            <div class="exposure-column-body">
              ${credentialPathPanel(riskPaths, identityExposure)}
            </div>
          </article>
        </div>
      </section>
      <section class="panel topology-panel">
        <div class="card-head">
          <div>
            <h2>Complete Topology Preview</h2>
            <p>Layered preview of collected assets and inferred edges. Large lanes are sampled to keep the graph readable.</p>
          </div>
          <span class="chip">${number(topology.assetCount)} ${escapeHTML(state.language === "zh" ? "个资产" : "assets")}</span>
        </div>
        ${topologyStage(topology)}
      </section>
      <section class="panel">
        <h2>Path Coverage</h2>
        ${relationshipCoverage(trafficExposure, relationships, graph, dataExposure, identityExposure, riskPaths)}
      </section>
    `;
  }

  async function renderScans() {
    const [runsPage, quality] = await Promise.all([
      api.scanRunsPage(pageRequest("scans")),
      api.scanQuality().catch(() => normalizeScanQuality(null)),
    ]);
    const runs = runsPage.items;
    const statusCounts = countBy(runs, "status");
    const qualitySummary = quality.summary || {};

    el.view.innerHTML = `
      ${metricCards([
        ["Runs", runsPage.total, "Scan runs matching filters", ""],
        ["Shown", runs.length, "Current page rows", ""],
        ["Succeeded", statusCounts.succeeded || 0, "Completed successfully", ""],
        ["Failed", statusCounts.failed || 0, "Runs needing inspection", "danger"],
      ])}
      <section class="content-grid equal">
        <article class="panel">
          <div class="card-head">
            <div>
              <h2>Scan Quality</h2>
              <p>Can users trust this run? Collection failures and rule coverage make that explicit.</p>
            </div>
            ${statusChip(qualitySummary.collectionHealth || "unknown")}
          </div>
          ${scanQualityPanel(quality)}
        </article>
        <article class="panel">
          <h2>Failure Categories</h2>
          ${keyValueChips(qualitySummary.failureCategories || {})}
          <h2>Resource Type Drilldown</h2>
          <p class="muted">Trust blockers grouped by product. Fix these before treating a clean result as complete.</p>
          ${scanQualityDrilldown(qualitySummary.resourceTypes || [])}
        </article>
      </section>
      <section class="table-card">
        <div class="card-head">
          <div>
            <h2>Scan Runs</h2>
            <p>Compact execution history from /api/scan-runs.</p>
          </div>
          <div class="chips">${keyValueChips(statusCounts)}</div>
        </div>
        ${listToolbar("scans", "Search scan runs", scanSortOptions())}
        ${scanRunsTable(runs)}
        ${paginationControls("scans", runsPage)}
      </section>
    `;
  }

  async function renderRules() {
    const [rulesPage, coverage] = await Promise.all([
      api.rulesPage(pageRequest("rules")),
      api.coverage(),
    ]);
    const rules = rulesPage.items;

    el.view.innerHTML = `
      ${metricCards([
        ["Rules", rulesPage.total || coverage.totalRules || 0, "Loaded rule definitions", ""],
        ["Shown", rules.length, "Current page rows", ""],
        ["Resource Types", coverage.resourceTypes || Object.keys(countBy(rules, "resource_type")).length, "Covered asset families", ""],
        ["With Examples", coverage.withExamples || 0, "Rules with input examples", ""],
      ])}
      <section class="coverage-grid">
        <article class="table-card">
          <div class="card-head">
            <div>
              <h2>Rule Catalog</h2>
              <p>Uses /api/rules when available. Empty state is expected on older Lite servers.</p>
            </div>
            <span class="chip">${number(rulesPage.total)} ${escapeHTML(state.language === "zh" ? "条规则" : "rules")}</span>
          </div>
          ${listToolbar("rules", "Search rules", ruleSortOptions())}
          ${rulesTable(rules)}
          ${paginationControls("rules", rulesPage)}
        </article>
        <aside class="panel">
          <h2>Coverage</h2>
          ${coverageSummary(coverage)}
          ${coverage.resources.length ? coverageTable(coverage.resources) : ""}
        </aside>
      </section>
    `;
  }

  async function renderSettings() {
    const [runtime, facets] = await Promise.all([
      api.runtime(),
      api.facets(),
    ]);
    state.runtime = runtime;
    state.facets = facets;
    applyRuntimeHealth(runtime);

    el.view.innerHTML = `
      <section class="content-grid">
        <article class="panel">
          <h2>Runtime</h2>
          ${runtimePanel(runtime)}
          <div class="json-block">${escapeHTML(JSON.stringify(runtime.raw || runtime, null, 2))}</div>
        </article>
        <article class="panel">
          <h2>Active Filters</h2>
          ${detailList(state.filters)}
          <h2>Facet Cache</h2>
          ${facetChips(facets)}
        </article>
      </section>
      <section class="content-grid equal">
        <article class="panel">
          <h2>Runbook</h2>
          <div class="json-block">cloudrec-lite serve --db ${escapeHTML(runtime.database || "<user-config>/cloudrec-lite/cloudrec-lite.db")} --provider ${escapeHTML(runtime.provider || "alicloud")} --addr 127.0.0.1:8787</div>
          <p class="muted">The Lite console is intentionally read-only. It never edits accounts, waivers, rules, or cloud resources.</p>
        </article>
        <article class="panel">
          <h2>Safety Notes</h2>
          ${detailList({
            database: runtime.database || "Not configured",
            rules: runtime.rulesDir || "Not configured",
            writes: "No write actions exposed in Web v1",
          })}
        </article>
      </section>
      <section class="panel">
        <h2>API Coverage</h2>
        <p class="muted">The UI calls the new Lite Web APIs and records whether a fallback was needed for older servers.</p>
        <div class="api-grid">${apiTiles()}</div>
      </section>
    `;
  }

  async function openDrawer(kind, item) {
    el.drawer.classList.add("open");
    el.drawer.setAttribute("aria-hidden", "false");
    el.drawerBackdrop.hidden = false;
    el.drawerKicker.textContent = kindLabel(kind) + " " + t("drawer.details");
    el.drawerTitle.textContent = titleFor(kind, item);
    el.drawerBody.innerHTML = `<div class="loading-state">${escapeHTML(state.language === "zh" ? "正在加载详情..." : "Loading detail...")}</div>`;

    try {
      let detail = item;
      if (kind === "finding") {
        detail = await api.finding(item);
      } else if (kind === "asset") {
        detail = await api.asset(item);
      }
      el.drawerTitle.textContent = titleFor(kind, detail);
      el.drawerBody.innerHTML = detailHTML(kind, detail);
      localizeRenderedText(el.drawerBody);
    } catch (error) {
      el.drawerBody.innerHTML = `<div class="error-state">${escapeHTML(error.message || (state.language === "zh" ? "无法加载详情" : "Unable to load detail"))}</div>${detailHTML(kind, item)}`;
      localizeRenderedText(el.drawerBody);
    }
  }

  function closeDrawer() {
    el.drawer.classList.remove("open");
    el.drawer.setAttribute("aria-hidden", "true");
    el.drawerBackdrop.hidden = true;
  }

  function detailHTML(kind, item) {
    const fields = detailFields(kind, item);
    return `
      <div class="chips">${detailChips(kind, item)}</div>
      ${kind === "finding" ? findingActionPanel(item) : ""}
      ${kind === "asset" ? assetProductSummaryPanel(item) : ""}
      ${detailList(fields)}
      <h3>${escapeHTML(state.language === "zh" ? "原始 JSON" : "Raw JSON")}</h3>
      <pre class="json-block">${escapeHTML(JSON.stringify(redactSensitiveJSON(item._raw || item), null, 2))}</pre>
    `;
  }

  function detailFields(kind, item) {
    if (kind === "finding") {
      return {
        id: item.id,
        title: item.title,
        severity: item.severity,
        status: item.status,
        rule_id: item.rule_id,
        asset_id: item.asset_id,
        account_id: item.account_id,
        resource_type: item.resource_type,
        message: item.message,
        remediation: item.remediation,
        first_seen_at: formatDate(item.first_seen_at),
        last_seen_at: formatDate(item.last_seen_at),
      };
    }
    if (kind === "asset") {
      return {
        id: item.id,
        name: item.name,
        provider: item.provider,
        account_id: item.account_id,
        resource_type: item.resource_type,
        resource_id: item.resource_id,
        region: item.region,
        first_seen_at: formatDate(item.first_seen_at),
        last_seen_at: formatDate(item.last_seen_at),
      };
    }
    if (kind === "relationship") {
      return {
        id: item.id,
        relationship_type: item.relationship_type,
        source_resource_type: item.source_resource_type,
        source_resource_id: item.source_resource_id,
        target_resource_id: item.target_resource_id,
        account_id: item.account_id,
        provider: item.provider,
        updated_at: formatDate(item.updated_at),
      };
    }
    if (kind === "scan") {
      return {
        id: item.id,
        status: item.status,
        provider: item.provider,
        account_id: item.account_id,
        started_at: formatDate(item.started_at),
        finished_at: formatDate(item.finished_at),
        assets: valueFrom(item.summary, ["assets", "asset_count"]),
        findings: valueFrom(item.summary, ["findings", "finding_count"]),
      };
    }
    return item;
  }

  function detailChips(kind, item) {
    if (kind === "finding") {
      return `${severityChip(item.severity)}${statusChip(item.status)}${chip(item.rule_id || "no rule")}`;
    }
    if (kind === "asset") {
      return `${chip(item.provider || "provider unknown")}${chip(item.resource_type || "type unknown")}${chip(item.region || "region unknown")}`;
    }
    if (kind === "relationship") {
      return `${chip(item.relationship_type || "relationship")}${chip(item.source_resource_type || "source")}`;
    }
    if (kind === "scan") {
      return `${statusChip(item.status)}${chip(item.provider || "provider unknown")}`;
    }
    return "";
  }

  function assetProductSummaryPanel(item) {
    const summary = item.productSummary || valueFrom(item._raw || {}, ["product_summary", "productSummary"], null);
    if (!summary || typeof summary !== "object" || !Object.keys(summary).length) {
      return "";
    }
    const product = stringValue(valueFrom(summary, ["product"], item.resource_type || "Asset"));
    const rows = Object.entries(summary)
      .filter(([key, value]) => !["product"].includes(key) && summaryValueVisible(value))
      .slice(0, 18);
    if (!rows.length) {
      return "";
    }
    return `
      <section class="product-summary-panel">
        <div class="product-summary-head">
          <span>${escapeHTML(state.language === "zh" ? "产品安全摘要" : "Product Security Summary")}</span>
          ${chip(product)}
        </div>
        <div class="product-summary-grid">
          ${rows.map(([key, value]) => `
            <div class="product-summary-item">
              <span class="meta-label">${escapeHTML(productSummaryLabel(key))}</span>
              ${productSummaryValue(key, value)}
            </div>
          `).join("")}
        </div>
      </section>
    `;
  }

  function summaryValueVisible(value) {
    if (value === undefined || value === null || value === "") {
      return false;
    }
    if (Array.isArray(value)) {
      return value.length > 0;
    }
    if (typeof value === "object") {
      return Object.keys(value).length > 0;
    }
    return true;
  }

  function productSummaryLabel(key) {
    const labels = state.language === "zh" ? {
      resource_type: "资源类型",
      region: "地域",
      acl: "ACL",
      block_public_access: "阻断公共访问",
      public_acl: "公开 ACL",
      policy_public: "公共策略",
      policy_write: "公共写策略",
      public_policy_statements: "公共策略数",
      policy_principals: "策略 Principal",
      effective_public: "实际公网开放",
      versioning: "版本控制",
      referer_count: "Referer 数",
      project_policy_public: "Project 公共策略",
      project_policy_write: "Project 公共写",
      logstore_count: "LogStore 数",
      alert_count: "告警数",
      public_endpoint: "公网端点",
      wide_whitelist: "宽松白名单",
      whitelist_count: "白名单条目",
      whitelist_preview: "白名单预览",
      engine: "引擎",
      version: "版本",
      network_type: "网络类型",
      status: "状态",
      public_ip_count: "公网 IP 数",
      public_ips: "公网 IP",
      security_group_count: "安全组数",
      security_groups: "安全组",
      instance_type: "实例规格",
      image_id: "镜像 ID",
      key_pair: "密钥对",
      disk_count: "磁盘数",
      active_ak_count: "活跃 AK 数",
      inactive_ak_count: "非活跃 AK 数",
      policy_count: "策略数",
      policy_document_count: "策略文档数",
      source_acl_status: "调用来源限制",
      source_conditions: "来源条件",
      high_risk_services: "高风险服务权限",
      address_type: "地址类型",
      public_entry: "公网入口",
      address: "地址",
      listener_count: "监听数",
      acl_off_listeners: "未启用 ACL 监听",
      backend_count: "后端数",
      rule_count: "规则数",
      wide_open_ingress_count: "公网开放入站",
      wide_open_ingress: "开放入站规则",
      collected_fields: "已采集字段",
    } : {};
    return labels[key] || key.replace(/_/g, " ");
  }

  function productSummaryValue(key, value) {
    if (typeof value === "boolean") {
      return `<span class="summary-bool ${value ? "yes" : ""}">${escapeHTML(value ? (state.language === "zh" ? "是" : "yes") : (state.language === "zh" ? "否" : "no"))}</span>`;
    }
    if (Array.isArray(value)) {
      if (!value.length) {
        return `<span class="muted">-</span>`;
      }
      const scalar = value.every((item) => item === null || typeof item !== "object");
      if (scalar) {
        return `<div class="chips">${value.slice(0, 8).map((item) => chip(displayValue(item))).join("")}</div>`;
      }
      return `<pre class="mini-json">${escapeHTML(JSON.stringify(redactSensitiveJSON(value.slice(0, 4)), null, 2))}</pre>`;
    }
    if (value && typeof value === "object") {
      return `<pre class="mini-json">${escapeHTML(JSON.stringify(redactSensitiveJSON(value), null, 2))}</pre>`;
    }
    if (key === "source_acl_status") {
      return statusChip(stringValue(value));
    }
    return `<strong>${escapeHTML(displayValue(value))}</strong>`;
  }

  function showLoading() {
    el.view.innerHTML = `
      <div class="skeleton-grid">
        <div class="skeleton"></div>
        <div class="skeleton"></div>
        <div class="skeleton"></div>
        <div class="skeleton"></div>
      </div>
    `;
  }

  function renderError(error) {
    el.view.innerHTML = `
      <section class="panel">
        <div class="error-state">
          <div>
            <h2>${escapeHTML(state.language === "zh" ? "无法加载" : "Unable to load")} ${escapeHTML(routeLabel(state.route))}</h2>
            <p>${escapeHTML(error.message || t("status.unknown"))}</p>
          </div>
        </div>
      </section>
    `;
    setStatus("Load failed");
  }

  function metricCards(items) {
    return `
      <section class="metrics-grid">
        ${items.map(([label, value, note, tone]) => `
          <article class="metric-card ${escapeHTML(tone || "")}">
            <div class="metric-value">${number(value)}</div>
            <div class="metric-label">${escapeHTML(label)}</div>
            <div class="metric-note">${escapeHTML(note || "")}</div>
          </article>
        `).join("")}
      </section>
    `;
  }

  function listToolbar(route, placeholder, sortOptions) {
    const page = pageState(route);
    return `
      <div class="list-toolbar">
        <label>
          <span>${escapeHTML(localPhrase("Search"))}</span>
          <input data-page-route="${escapeHTML(route)}" data-page-field="q" value="${escapeHTML(page.q || "")}" placeholder="${escapeHTML(localPhrase(placeholder))}">
        </label>
        <label>
          <span>${escapeHTML(localPhrase("Sort"))}</span>
          <select data-page-route="${escapeHTML(route)}" data-page-field="sort">
            ${sortOptions.map((option) => `<option value="${escapeHTML(option.value)}" ${option.value === page.sort ? "selected" : ""}>${escapeHTML(localPhrase(option.label))}</option>`).join("")}
          </select>
        </label>
      </div>
    `;
  }

  function trafficPathToolbar() {
    const page = pageState("relationships");
    return `
      <div class="traffic-toolbar">
        <label>
          <span>${escapeHTML(localPhrase("Search"))}</span>
          <input data-page-route="relationships" data-page-field="q" value="${escapeHTML(page.q || "")}" placeholder="${escapeHTML(localPhrase("Search exposed paths"))}">
        </label>
        <label>
          <span>${escapeHTML(localPhrase("Port"))}</span>
          <input data-page-route="relationships" data-page-field="port" value="${escapeHTML(page.port || "")}" placeholder="${escapeHTML(localPhrase("Any port"))}">
        </label>
        <label>
          <span>${escapeHTML(localPhrase("Open policy"))}</span>
          <select data-page-route="relationships" data-page-field="open_policy">
            <option value="" ${!page.open_policy ? "selected" : ""}>${escapeHTML(localPhrase("Any policy"))}</option>
            <option value="true" ${page.open_policy === "true" ? "selected" : ""}>${escapeHTML(localPhrase("Wide open only"))}</option>
            <option value="false" ${page.open_policy === "false" ? "selected" : ""}>${escapeHTML(localPhrase("Restricted only"))}</option>
          </select>
        </label>
      </div>
    `;
  }

  function paginationControls(route, page) {
    const limit = page.limit || pageLimit();
    const start = page.total && page.count ? page.offset + 1 : 0;
    const end = Math.min(page.total || page.offset + page.count, page.offset + page.count);
    const hasPrev = page.offset > 0;
    const hasNext = page.offset + page.count < page.total;
    return `
      <div class="pagination-bar">
        <span>${escapeHTML(localPhrase("Showing"))} ${number(start)}-${number(end)} ${escapeHTML(localPhrase("of"))} ${number(page.total)}</span>
        <div class="pager-buttons">
          <button class="button ghost" type="button" data-page-route="${escapeHTML(route)}" data-page-action="prev" ${hasPrev ? "" : "disabled"}>${escapeHTML(localPhrase("Previous"))}</button>
          <button class="button ghost" type="button" data-page-route="${escapeHTML(route)}" data-page-action="next" ${hasNext && limit ? "" : "disabled"}>${escapeHTML(localPhrase("Next"))}</button>
        </div>
      </div>
    `;
  }

  function riskSortOptions() {
    return [
      { value: "", label: "Newest first" },
      { value: "last_seen_at", label: "Oldest first" },
      { value: "-severity", label: "Highest severity" },
      { value: "severity", label: "Lowest severity" },
      { value: "rule_id", label: "Rule ID" },
      { value: "title", label: "Title A-Z" },
    ];
  }

  function assetSortOptions() {
    return [
      { value: "", label: "Newest first" },
      { value: "last_seen_at", label: "Oldest first" },
      { value: "name", label: "Name A-Z" },
      { value: "resource_type", label: "Type A-Z" },
      { value: "region", label: "Region A-Z" },
      { value: "resource_id", label: "Resource ID A-Z" },
    ];
  }

  function scanSortOptions() {
    return [
      { value: "", label: "Started newest" },
      { value: "started_at", label: "Started oldest" },
      { value: "status", label: "Status A-Z" },
      { value: "provider", label: "Provider A-Z" },
    ];
  }

  function ruleSortOptions() {
    return [
      { value: "", label: "Rule ID" },
      { value: "-severity", label: "Highest severity" },
      { value: "severity", label: "Lowest severity" },
      { value: "resource_type", label: "Type A-Z" },
      { value: "title", label: "Title A-Z" },
      { value: "status", label: "Status A-Z" },
    ];
  }

  function findingsTable(findings) {
    if (!findings.length) {
      return emptyTable("No findings match the active filters.");
    }
    return table(["Severity", "Status", "Rule", "Asset", "Title", "Last Seen"], findings.map((item) => {
      const key = cacheItem("finding", item);
      return `
        <tr data-key="${escapeHTML(key)}">
          <td>${severityChip(item.severity)}</td>
          <td>${statusChip(item.status)}</td>
          <td><code>${escapeHTML(item.rule_id)}</code></td>
          <td class="truncate"><code>${escapeHTML(item.asset_id || item.resource_id)}</code></td>
          <td class="truncate">${escapeHTML(item.title || item.message)}</td>
          <td>${escapeHTML(formatDate(item.last_seen_at || item.updated_at))}</td>
        </tr>
      `;
    }));
  }

  function assetsTable(assets) {
    if (!assets.length) {
      return emptyTable("No assets match the active filters.");
    }
    return table(["Type", "Name", "Provider", "Region", "Resource ID", "Last Seen"], assets.map((item) => {
      const key = cacheItem("asset", item);
      return `
        <tr data-key="${escapeHTML(key)}">
          <td>${chip(item.resource_type || "unknown")}</td>
          <td class="truncate">${escapeHTML(item.name || item.resource_id || item.id)}</td>
          <td>${escapeHTML(item.provider || "")}</td>
          <td>${escapeHTML(item.region || "global")}</td>
          <td class="truncate"><code>${escapeHTML(item.resource_id || item.id)}</code></td>
          <td>${escapeHTML(formatDate(item.last_seen_at || item.updated_at))}</td>
        </tr>
      `;
    }));
  }

  function relationshipsTable(relationships) {
    if (!relationships.length) {
      return emptyTable("No relationships match the active filters.");
    }
    return table(["Type", "Source Type", "Source", "Target", "Updated"], relationships.map((item) => {
      const key = cacheItem("relationship", item);
      return `
        <tr data-key="${escapeHTML(key)}">
          <td>${chip(item.relationship_type || "linked")}</td>
          <td>${escapeHTML(item.source_resource_type || "")}</td>
          <td class="truncate"><code>${escapeHTML(item.source_resource_id)}</code></td>
          <td class="truncate"><code>${escapeHTML(item.target_resource_id)}</code></td>
          <td>${escapeHTML(formatDate(item.updated_at || item.last_seen_at))}</td>
        </tr>
      `;
    }));
  }

  function scanRunsTable(runs) {
    if (!runs.length) {
      return emptyTable("No scan runs match the active filters.");
    }
    return table(["Started", "Status", "Provider", "Assets", "Findings", "Finished"], runs.map((item) => {
      const key = cacheItem("scan", item);
      return `
        <tr data-key="${escapeHTML(key)}">
          <td>${escapeHTML(formatDate(item.started_at || item.created_at))}</td>
          <td>${statusChip(item.status)}</td>
          <td>${escapeHTML(item.provider || "")}</td>
          <td>${number(valueFrom(item.summary, ["assets", "asset_count"], ""))}</td>
          <td>${number(valueFrom(item.summary, ["findings", "finding_count"], ""))}</td>
          <td>${escapeHTML(formatDate(item.finished_at))}</td>
        </tr>
      `;
    }));
  }

  function rulesTable(rules) {
    if (!rules.length) {
      return emptyTable("No rule catalog API response yet.");
    }
    return table(["Rule", "Severity", "Resource", "Provider", "Status"], rules.map((item) => {
      const key = cacheItem("rule", item);
      return `
        <tr data-key="${escapeHTML(key)}">
          <td class="truncate"><code>${escapeHTML(item.id)}</code><br>${escapeHTML(item.title)}</td>
          <td>${severityChip(item.severity)}</td>
          <td>${chip(item.resource_type || "unknown")}</td>
          <td>${escapeHTML(item.provider || "")}</td>
          <td>${statusChip(item.status || (item.enabled === false ? "disabled" : "enabled"))}</td>
        </tr>
      `;
    }));
  }

  function coverageTable(resources) {
    return `
      <div class="table-wrap">
        <table>
          <thead><tr><th>Resource</th><th>Rules</th><th>Review</th><th>Fields</th><th>Fix</th><th>Native</th></tr></thead>
          <tbody>
            ${resources.slice(0, 10).map((row) => `
              <tr>
                <td>${escapeHTML(row.resource_type || row.normalized || "unknown")}</td>
                <td>${number(row.total_rules)}</td>
                <td>${coverageReviewCell(row)}</td>
                <td>${collectorFieldChip(row.collector_field_status, row.missing_sample_refs)}</td>
                <td>${qualityRatio(row.with_remediation, row.total_rules)}</td>
                <td>${row.native_adapter ? (state.language === "zh" ? "是" : "yes") : (state.language === "zh" ? "否" : "no")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  function table(headers, rows) {
    return `
      <div class="table-wrap">
        <table>
          <thead><tr>${headers.map((header) => `<th>${escapeHTML(header)}</th>`).join("")}</tr></thead>
          <tbody>${rows.join("")}</tbody>
        </table>
      </div>
    `;
  }

  function emptyTable(message) {
    return `<div class="empty-state">${escapeHTML(message)}</div>`;
  }

  function severityBars(counts) {
    const normalized = counts || {};
    const max = Math.max(1, ...severityOrder.map((severity) => Number(normalized[severity] || 0)));
    return `
      <div class="severity-bars">
        ${severityOrder.map((severity) => {
          const count = Number(normalized[severity] || 0);
          return `
            <div class="severity-row">
              <span>${escapeHTML(translateValue("severity", severity))}</span>
              <div class="bar-track"><div class="bar-fill ${escapeHTML(severity)}" style="width:${Math.max(3, Math.round((count / max) * 100))}%"></div></div>
              <strong>${number(count)}</strong>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  function deltaGrid(delta) {
    const values = delta || {};
    return `
      <div class="delta-grid">
        ${[
          ["Added", values.added_assets || values.addedAssets || 0],
          ["Updated", values.updated_assets || values.updatedAssets || 0],
          ["Missing", values.missing_assets || values.missingAssets || 0],
          ["Seen", values.seen_assets || values.seenAssets || 0],
        ].map(([label, value]) => `
          <div class="mini-card">
            <div class="mini-value">${number(value)}</div>
            <div class="metric-label">${escapeHTML(label)}</div>
          </div>
        `).join("")}
      </div>
    `;
  }

  function facetChips(facets) {
    const groups = [];
    if (facets.accounts.length) {
      groups.push(["Accounts", facets.accounts]);
    }
    if (facets.resourceTypes.length) {
      groups.push(["Resources", facets.resourceTypes]);
    }
    if (facets.providers.length) {
      groups.push(["Providers", facets.providers]);
    }
    if (!groups.length) {
      return `<p class="muted">No facet values returned yet.</p>`;
    }
    return groups.map(([label, values]) => `
      <p class="meta-label">${escapeHTML(label)}</p>
      <div class="chips">${values.slice(0, 8).map((item) => chip(item.label, item.count)).join("")}</div>
    `).join("");
  }

  function keyValueChips(values) {
    const entries = Object.entries(values || {}).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
      return `<p class="muted">No values.</p>`;
    }
    return `<div class="chips">${entries.slice(0, 16).map(([key, value]) => chip(key || "unknown", value)).join("")}</div>`;
  }

  function scanSummary(runs) {
    if (!runs.length) {
      return `<p class="muted">No recent scan runs.</p>`;
    }
    return `
      <p class="muted">${escapeHTML(localPhrase("Scan runs stored in the current database."))}</p>
      <div class="scan-summary-list">
        ${runs.map((run) => {
          const started = run.started_at || run.created_at;
          const finished = run.finished_at || run.updated_at;
          return `
            <article class="scan-summary-item">
              <div class="scan-summary-head">
                <div>
                  <span class="meta-label">${escapeHTML(localPhrase("Run"))}</span>
                  <code>${escapeHTML(shortRunID(run.id))}</code>
                </div>
                <div>${statusChip(run.status)} ${chip(run.provider || "provider unknown")}</div>
              </div>
              <div class="detail-list compact">
                ${detailRow("Started", formatDate(started))}
                ${finished ? detailRow("Finished", formatDate(finished)) : ""}
                ${detailRow("Duration", durationBetween(started, finished))}
                ${detailRow("Assets", valueFrom(run.summary, ["assets", "asset_count"], ""))}
                ${detailRow("Findings", valueFrom(run.summary, ["findings", "finding_count"], ""))}
              </div>
            </article>
          `;
        }).join("")}
      </div>
    `;
  }

  function scanQualityPanel(quality) {
    if (!quality.available) {
      return `<div class="empty-state">${escapeHTML(state.language === "zh" ? "当前服务尚未提供扫描质量接口。" : "Scan quality API is not available yet.")}</div>`;
    }
    const summary = quality.summary || {};
    const coverage = Math.round(numberValue(summary.evaluationCoverage) * 100);
    const ruleQuality = summary.ruleQuality || {};
    const ruleQualityStatus = summary.ruleQualityStatus || "unknown";
    return `
      <div class="delta-grid">
        <div class="mini-card"><div class="mini-value">${escapeHTML(localPhrase(summary.collectionHealth || "unknown"))}</div><div class="metric-label">${escapeHTML(localPhrase("Collection Health"))}</div></div>
        <div class="mini-card"><div class="mini-value">${number(coverage)}%</div><div class="metric-label">${escapeHTML(localPhrase("Rule Coverage"))}</div></div>
        <div class="mini-card"><div class="mini-value">${escapeHTML(localPhrase(ruleQualityStatus))}</div><div class="metric-label">${escapeHTML(localPhrase("Rule Quality"))}</div></div>
        <div class="mini-card"><div class="mini-value">${number(summary.collectionFailures || 0)}</div><div class="metric-label">${escapeHTML(localPhrase("Collection Failures"))}</div></div>
      </div>
      ${ruleQualityStatus && ruleQualityStatus !== "unknown" ? `
        <div class="detail-list compact">
          ${detailRow("Official Reviewed", `${number(ruleQuality.officialReviewed || 0)} / ${number(ruleQuality.totalRules || 0)}`)}
          ${detailRow("Blocked", ruleQuality.blocked || 0)}
          ${detailRow("Needs Logic Change", ruleQuality.needsLogicChange || 0)}
          ${detailRow("Missing Sample Refs", ruleQuality.missingSampleRefs || 0)}
          ${detailRow("Missing Data Refs", ruleQuality.missingDataRefs || 0)}
          ${detailRow("Missing Remediation", ruleQuality.missingRemediation || 0)}
        </div>
      ` : ""}
      ${quality.latestRun ? `
        <div class="detail-list">
          ${detailRow("Latest scan", quality.latestRun.id)}
          ${detailRow("Status", quality.latestRun.status)}
          ${detailRow("Assets", quality.latestRun.assets)}
          ${detailRow("Findings", quality.latestRun.findings)}
        </div>
      ` : ""}
    `;
  }

  function qualityFacetChips(values) {
    if (!values.length) {
      return `<p class="muted">${escapeHTML(state.language === "zh" ? "暂无失败资源类型。" : "No failed resource types.")}</p>`;
    }
    return `<div class="chips">${values.slice(0, 10).map((item) => chip(item.value || item.label, item.count)).join("")}</div>`;
  }

  function scanQualityDrilldown(values) {
    if (!values.length) {
      return `<p class="muted">${escapeHTML(localPhrase("No resource-type blockers."))}</p>`;
    }
    return `
      <div class="quality-drilldown">
        ${values.slice(0, 8).map((item) => `
          <article class="quality-resource-card">
            <div class="quality-resource-head">
              <strong>${escapeHTML(item.resourceType || item.value || "unknown")}</strong>
              ${statusChip(item.status || "failed")}
            </div>
            <div class="chips">
              ${chip("failures", item.failures)}
              ${Object.entries(item.categories || {}).slice(0, 4).map(([category, count]) => chip(localPhrase(category), count)).join("")}
            </div>
            ${item.hint ? `<p class="muted">${escapeHTML(localPhrase(item.hint))}</p>` : ""}
          </article>
        `).join("")}
      </div>
    `;
  }

  function coverageSummary(coverage) {
    if (!coverage || (!coverage.totalRules && !coverage.resourceTypes && !coverage.resources.length)) {
      return `<p class="muted">Coverage API is not available yet, or returned no rules.</p>`;
    }
    return `
      <div class="delta-grid">
        <div class="mini-card"><div class="mini-value">${number(coverage.totalRules)}</div><div class="metric-label">Rules</div></div>
        <div class="mini-card"><div class="mini-value">${number(coverage.officialReviewed)}</div><div class="metric-label">Official Reviewed</div></div>
        <div class="mini-card"><div class="mini-value">${number(coverage.verifiedResources)}</div><div class="metric-label">Field Verified</div></div>
        <div class="mini-card"><div class="mini-value">${number(numberValue(coverage.missingSampleRefs) + numberValue(coverage.missingDataRefs))}</div><div class="metric-label">Missing</div></div>
      </div>
    `;
  }

  function runtimePanel(runtime) {
    const status = runtime.status || "unknown";
    return `
      <div class="chips">
        ${statusChip(status)}
        ${chip(runtime.version || "version unknown")}
        ${chip(runtime.mode || runtime.provider || "local")}
      </div>
      <div class="detail-list">
        ${detailRow("API", runtime.api || runtime.endpoint || "local")}
        ${detailRow("Database", runtime.database || runtime.store || "unknown")}
        ${detailRow("Rules", runtime.rulesDir || "unknown")}
        ${detailRow("Updated", formatDate(runtime.updated_at || runtime.checked_at || new Date().toISOString()))}
      </div>
    `;
  }

  function firstRunPanel(runtime, dashboard, scans) {
    const hasData = numberValue(dashboard.assetCount) > 0 ||
      numberValue(dashboard.findingCount) > 0 ||
      numberValue(dashboard.relationshipCount) > 0 ||
      scans.length > 0;
    if (hasData) {
      return "";
    }
    const provider = runtime.provider || "alicloud";
    const rulesDir = runtime.rulesDir || "./rules/alicloud";
    const db = runtime.database || "<user-config>/cloudrec-lite/cloudrec-lite.db";
    return `
      <section class="panel first-run-panel">
        <div class="card-head">
          <div>
            <h2>First Run Guide</h2>
            <p>No scan data is stored yet. Run these commands locally to validate setup, scan, and reopen this console.</p>
          </div>
          ${chip("read-only")}
        </div>
        <div class="detail-list">
          ${commandRow("1. Store Credentials", `cloudrec-lite credentials store --provider ${provider} --account <account-id> --access-key-id-stdin`)}
          ${commandRow("2. Doctor", `cloudrec-lite doctor --provider ${provider} --account <account-id> --db ${db}`)}
          ${commandRow("3. Scan", `cloudrec-lite scan --provider ${provider} --account <account-id> --db ${db} --dry-run=false`)}
          ${commandRow("4. Serve", `cloudrec-lite serve --db ${db} --provider ${provider}`)}
        </div>
        <p class="muted">Credentials stay in your OS credential store or one-shot shell environment and are never shown in this page.</p>
      </section>
    `;
  }

  function commandRow(label, command) {
    return `
      <div class="detail-row">
        <span class="meta-label">${escapeHTML(localPhrase(label))}</span>
        <span><code>${escapeHTML(command)}</code></span>
      </div>
    `;
  }

  function findingActionPanel(item) {
    const provider = item.provider || state.runtime.provider || "alicloud";
    const account = item.account_id || state.filters.account || "<account-id>";
    const resourceType = item.resource_type || item.asset_resource_type || "";
    const command = [
      "cloudrec-lite scan",
      `--provider ${shellToken(provider)}`,
      `--account ${shellToken(account)}`,
      resourceType ? `--resource-types ${shellToken(resourceType)}` : "",
      "--dry-run=true",
    ].filter(Boolean).join(" ");
    return `
      <section class="mini-remediation">
        <h3>${escapeHTML(state.language === "zh" ? "修复上下文" : "Remediation Context")}</h3>
        ${item.message ? `<p>${escapeHTML(item.message)}</p>` : ""}
        ${item.remediation ? `<p class="muted">${escapeHTML(item.remediation)}</p>` : ""}
        <pre class="json-block">${escapeHTML(command)}</pre>
      </section>
    `;
  }

  function graphStage(graph) {
    if (!graph.nodes.length) {
      return `<div class="empty-state">No graph nodes available.</div>`;
    }

    const width = 420;
    const height = 350;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.36;
    const nodes = graph.nodes.slice(0, 18).map((node, index, all) => {
      const angle = (Math.PI * 2 * index) / Math.max(1, all.length);
      return {
        ...node,
        x: Math.round(centerX + Math.cos(angle) * radius),
        y: Math.round(centerY + Math.sin(angle) * radius),
      };
    });
    const nodeIndex = new Map(nodes.map((node) => [node.id, node]));
    const links = graph.edges
      .map((edge) => ({ source: nodeIndex.get(edge.source), target: nodeIndex.get(edge.target), type: edge.type }))
      .filter((edge) => edge.source && edge.target)
      .slice(0, 28);

    return `
      <div class="graph-stage">
        <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Asset relationship graph">
          ${links.map((edge) => `<line class="graph-link" x1="${edge.source.x}" y1="${edge.source.y}" x2="${edge.target.x}" y2="${edge.target.y}"></line>`).join("")}
          ${nodes.map((node) => `
            <g>
              <circle class="graph-node" cx="${node.x}" cy="${node.y}" r="22"></circle>
              <text class="graph-label" x="${node.x}" y="${node.y + 4}" text-anchor="middle">${escapeHTML(shortLabel(node.label || node.id))}</text>
            </g>
          `).join("")}
        </svg>
      </div>
      <p class="muted">${state.language === "zh"
        ? `${number(graph.nodes.length)} 个节点，${number(graph.edges.length)} 条边。当前展示轻量本地布局。`
        : `${number(graph.nodes.length)} nodes and ${number(graph.edges.length)} edges. Showing a compact local layout.`}</p>
    `;
  }

  function buildExposureModel(assets, relationships) {
    const assetIndex = buildAssetIndex(assets);
    const securityGroupsByECS = groupSecurityGroupsByECS(relationships, assetIndex);
    const entries = assets
      .filter((asset) => isLoadBalancer(asset.resource_type))
      .map((asset) => loadBalancerEntry(asset, assetIndex, securityGroupsByECS));
    const paths = entries
      .filter((entry) => entry.isPublic)
      .sort((left, right) => Number(right.hasOpenPolicy) - Number(left.hasOpenPolicy) || right.backends.length - left.backends.length);
    const backendKeys = new Set();
    const securityGroupKeys = new Set();
    const openPolicyKeys = new Set();
    let backendsWithoutSecurityGroup = 0;
    paths.forEach((path) => {
      path.backends.forEach((backend) => {
        backendKeys.add(backend.key);
        if (!backend.securityGroups.length) {
          backendsWithoutSecurityGroup += 1;
        }
        backend.securityGroups.forEach((group) => {
          securityGroupKeys.add(group.key);
          group.openPolicies.forEach((policy, index) => {
            openPolicyKeys.add(policy.id || `${group.key}:${index}:${policy.source}:${policy.protocol}:${policy.port}`);
          });
        });
      });
    });

    return {
      entries,
      paths,
      publicEntryCount: paths.length,
      backendECSCount: backendKeys.size,
      securityGroupCount: securityGroupKeys.size,
      openPolicyCount: openPolicyKeys.size,
      missingBackendCount: paths.filter((path) => !path.backends.length).length,
      backendsWithoutSecurityGroup,
      aclOffCount: paths.reduce((total, path) => total + path.listeners.filter((listener) => listener.aclOff).length, 0),
    };
  }

  function buildAssetIndex(assets) {
    const byResourceID = new Map();
    const byNativeID = new Map();
    assets.forEach((asset) => {
      [asset.id, asset.resource_id].filter(Boolean).forEach((id) => {
        byResourceID.set(id, asset);
      });
      assetNativeIDs(asset).forEach((id) => {
        const key = lower(id);
        const items = byNativeID.get(key) || [];
        items.push(asset);
        byNativeID.set(key, items);
      });
    });
    return { byResourceID, byNativeID };
  }

  function groupSecurityGroupsByECS(relationships, assetIndex) {
    const grouped = new Map();
    relationships.forEach((relationship) => {
      if (!looksLikeSecurityGroupID(relationship.target_resource_id)) {
        return;
      }
      const ecsAsset = resolveAsset(assetIndex, relationship.source_resource_id, "ECS");
      const groupAsset = resolveAsset(assetIndex, relationship.target_resource_id, "Security Group");
      const group = securityGroupSummary(groupAsset, relationship.target_resource_id);
      [
        relationship.source_resource_id,
        nativeID(relationship.source_resource_id),
        ecsAsset && ecsAsset.resource_id,
        ecsAsset && nativeID(ecsAsset.resource_id),
      ].filter(Boolean).forEach((id) => {
        const key = lower(id);
        const items = grouped.get(key) || [];
        if (!items.some((item) => item.key === group.key)) {
          items.push(group);
        }
        grouped.set(key, items);
      });
    });
    return grouped;
  }

  function loadBalancerEntry(asset, assetIndex, securityGroupsByECS) {
    const properties = parseMaybeJSON(asset.properties) || {};
    const attributes = properties.attributes || properties.Attributes || properties;
    const loadBalancer = firstObject([
      attributes.LoadBalancerAttribute,
      attributes.LoadBalancer,
      attributes.loadBalancerAttribute,
      attributes.loadBalancer,
    ]);
    const addressType = stringValue(valueFrom(loadBalancer, ["AddressType", "addressType"], ""));
    const listeners = extractListeners(attributes);
    const backends = extractBackendRefs(attributes).map((backend) => {
      const ecsAsset = resolveAsset(assetIndex, backend.id, "ECS", asset.region);
      const ecsResourceID = ecsAsset && ecsAsset.resource_id ? ecsAsset.resource_id : backend.id;
      const securityGroups = dedupeByKey([
        ...(securityGroupsByECS.get(lower(ecsResourceID)) || []),
        ...(securityGroupsByECS.get(lower(nativeID(ecsResourceID))) || []),
        ...(securityGroupsByECS.get(lower(backend.id)) || []),
      ]);
      return {
        ...backend,
        key: ecsResourceID || backend.id,
        asset: ecsAsset,
        name: (ecsAsset && ecsAsset.name) || backend.id,
        resourceID: ecsResourceID,
        nativeID: nativeID(ecsResourceID || backend.id),
        region: (ecsAsset && ecsAsset.region) || asset.region,
        securityGroups,
      };
    });
    const isPublic = isPublicAddress(addressType) || hasPublicAddress(loadBalancer);
    const hasOpenPolicy = backends.some((backend) => backend.securityGroups.some((group) => group.openPolicies.length));

    return {
      asset,
      key: asset.resource_id || asset.id,
      type: asset.resource_type || "SLB",
      name: asset.name || nativeID(asset.resource_id) || asset.id,
      resourceID: asset.resource_id || asset.id,
      nativeID: nativeID(asset.resource_id || asset.id),
      region: asset.region || stringValue(valueFrom(loadBalancer, ["RegionId"], "")),
      address: firstNonEmpty([
        valueFrom(loadBalancer, ["Address", "DNSName"], ""),
        firstLoadBalancerAddress(loadBalancer),
      ]),
      addressType,
      isPublic,
      listeners,
      backends,
      hasOpenPolicy,
    };
  }

  function exposureFromTrafficPaths(trafficPaths) {
    const paths = (trafficPaths || []).map((path) => trafficPathToExposurePath(path));
    const backendKeys = new Set();
    const securityGroupKeys = new Set();
    paths.forEach((path) => {
      path.backends.forEach((backend) => {
        backendKeys.add(backend.key);
        backend.securityGroups.forEach((group) => securityGroupKeys.add(group.key));
      });
    });
    return {
      entries: paths,
      paths,
      publicEntryCount: paths.length,
      backendECSCount: backendKeys.size,
      securityGroupCount: securityGroupKeys.size,
      openPolicyCount: paths.reduce((total, path) => total + numberValue(path.openPolicyCount), 0),
      cloudFirewallAllowCount: paths.reduce((total, path) => total + numberValue(path.cloudFirewallAllowCount), 0),
      cloudFirewallDropCount: paths.reduce((total, path) => total + numberValue(path.cloudFirewallDropCount), 0),
      missingBackendCount: paths.reduce((total, path) => total + numberValue(path.missingBackendCount), 0),
      backendsWithoutSecurityGroup: paths.reduce((total, path) => total + numberValue(path.missingSGCount), 0),
      aclOffCount: paths.reduce((total, path) => total + path.listeners.filter((listener) => listener.aclOff).length, 0),
      backendAuthoritative: true,
    };
  }

  function trafficPathToExposurePath(path) {
    const entry = path.entry || {};
    return {
      asset: riskAssetSummaryToAsset(entry),
      key: entry.resource_id || entry.id || path.id,
      type: entry.resource_type || "SLB",
      name: entry.name || nativeID(entry.resource_id) || entry.id || "Load Balancer",
      resourceID: entry.resource_id || entry.id,
      nativeID: nativeID(entry.resource_id || entry.id),
      region: path.region || entry.region || "global",
      address: path.address || "",
      addressType: path.addressType || "",
      isPublic: true,
      listeners: (path.listeners || []).map((listener) => ({
        port: listener.port,
        protocol: listener.protocol,
        status: listener.status,
        aclStatus: listener.aclStatus,
        aclType: listener.aclType,
        aclOff: Boolean(listener.aclOff),
      })),
      backends: (path.backends || []).map((backend) => ({
        key: backend.resourceID || backend.nativeID || backend.name,
        asset: backend.asset ? riskAssetSummaryToAsset(backend.asset) : null,
        name: backend.name || nativeID(backend.resourceID) || backend.nativeID,
        resourceID: backend.resourceID,
        nativeID: backend.nativeID || nativeID(backend.resourceID),
        port: backend.port,
        weight: backend.weight,
        status: backend.status,
        securityGroups: (backend.securityGroups || []).map((group) => ({
          key: group.resourceID || group.nativeID || group.name,
          asset: group.asset ? riskAssetSummaryToAsset(group.asset) : null,
          name: group.name || group.nativeID,
          resourceID: group.resourceID,
          nativeID: group.nativeID || nativeID(group.resourceID),
          policies: (group.policies || []).map(normalizeTrafficPolicy),
          openPolicies: (group.openPolicies || []).map(normalizeTrafficPolicy),
        })),
      })),
      cloudFirewallPolicies: (path.cloudFirewallPolicies || []).map(normalizeTrafficFirewallPolicy),
      cloudFirewallAllowCount: numberValue(path.cloudFirewallAllowCount),
      cloudFirewallDropCount: numberValue(path.cloudFirewallDropCount),
      hasOpenPolicy: numberValue(path.openPolicyCount) > 0,
      openPolicyCount: numberValue(path.openPolicyCount),
      missingBackendCount: numberValue(path.missingBackendCount),
      missingSGCount: numberValue(path.missingSGCount),
    };
  }

  function normalizeTrafficFirewallPolicy(policy) {
    return {
      asset: normalizeRiskPathAsset(valueFrom(policy, ["asset"], null)),
      resourceID: stringValue(valueFrom(policy, ["resource_id", "resourceId"], "")),
      nativeID: stringValue(valueFrom(policy, ["native_id", "nativeId"], "")),
      direction: stringValue(valueFrom(policy, ["direction"], "")),
      action: stringValue(valueFrom(policy, ["action"], "")),
      source: stringValue(valueFrom(policy, ["source"], "")),
      destination: stringValue(valueFrom(policy, ["destination"], "")),
      protocol: stringValue(valueFrom(policy, ["protocol"], "")),
      port: stringValue(valueFrom(policy, ["port"], "")),
      order: stringValue(valueFrom(policy, ["order"], "")),
      description: stringValue(valueFrom(policy, ["description"], "")),
      open: truthy(valueFrom(policy, ["open"], false)),
      drop: truthy(valueFrom(policy, ["drop"], false)),
    };
  }

  function normalizeTrafficPolicy(policy) {
    return {
      id: stringValue(valueFrom(policy, ["id"], "")),
      direction: stringValue(valueFrom(policy, ["direction"], "")),
      action: stringValue(valueFrom(policy, ["action"], "")),
      source: stringValue(valueFrom(policy, ["source"], "")),
      protocol: stringValue(valueFrom(policy, ["protocol"], "")),
      port: stringValue(valueFrom(policy, ["port"], "")),
      priority: stringValue(valueFrom(policy, ["priority"], "")),
      description: stringValue(valueFrom(policy, ["description"], "")),
      open: truthy(valueFrom(policy, ["open"], false)),
    };
  }

  function riskAssetSummaryToAsset(summary) {
    return normalizeAsset({
      id: summary.id,
      account_id: summary.account_id,
      provider: summary.provider,
      resource_type: summary.resource_type,
      resource_id: summary.resource_id,
      region: summary.region,
      name: summary.name,
    });
  }

  function networkExposureTopology(exposure) {
    if (!exposure.paths.length) {
      return `<div class="empty-state">No load balancer paths available.</div>`;
    }
    const visiblePaths = exposure.paths.slice(0, 6);
    const hidden = Math.max(0, exposure.paths.length - visiblePaths.length);
    return `
      <div class="network-topology-list">
        ${visiblePaths.map((path, index) => networkExposurePathCard(path, index)).join("")}
      </div>
      ${hidden ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hidden)} 条公网入口链路未展示。` : `${number(hidden)} more public entry paths are hidden.`}</p>` : ""}
      <p class="muted">${escapeHTML(localPhrase("Click a node to open asset details. Expand a path to inspect listeners, backends, and security-group policies."))}</p>
    `;
  }

  function networkExposurePathCard(path, index) {
    const openRuleCount = openPolicyCountForPath(path);
    const listenerOffCount = path.listeners.filter((listener) => listener.aclOff).length;
    const cloudfwCount = path.cloudFirewallPolicies ? path.cloudFirewallPolicies.length : 0;
    const danger = openRuleCount > 0;
    return `
      <details class="flow-card ${danger ? "danger" : ""}" ${index < 2 ? "open" : ""}>
        <summary class="flow-summary">
          <span>
            <strong>${escapeHTML(path.type)} · ${escapeHTML(path.name)}</strong>
            <code>${escapeHTML(path.address || path.nativeID || path.resourceID)}</code>
          </span>
          <span class="flow-summary-chips">
            ${chip(path.region || "global")}
            ${chip("listeners", path.listeners.length)}
            ${chip("backends", path.backends.length)}
            ${cloudfwCount ? chip("CloudFW", cloudfwCount) : ""}
            ${listenerOffCount ? chip("ACL off", listenerOffCount) : ""}
            ${openRuleCount ? chip("wide open", openRuleCount) : ""}
            <span class="flow-toggle flow-open">${escapeHTML(localPhrase("Open path details"))}</span>
            <span class="flow-toggle flow-close">${escapeHTML(localPhrase("Collapse path details"))}</span>
          </span>
        </summary>
        ${networkFlowDiagram(path, index)}
        <div class="flow-drilldown">
          ${exposurePath(path)}
        </div>
      </details>
    `;
  }

  function networkFlowDiagram(path, index) {
    const rows = path.backends.length ? path.backends.slice(0, 4) : [null];
    const hiddenBackends = Math.max(0, path.backends.length - rows.filter(Boolean).length);
    const width = 1300;
    const nodeWidth = 150;
    const nodeHeight = 58;
    const rowGap = 96;
    const firstY = 92;
    const centerY = firstY + ((rows.length - 1) * rowGap) / 2;
    const height = Math.max(230, firstY + (rows.length - 1) * rowGap + 104);
    const markerID = `flow-arrow-${stableID(path.resourceID || path.key || index)}`;
    const x = {
      internet: 18,
      cloudfw: 190,
      entry: 372,
      listener: 554,
      compute: 736,
      policy: 918,
      decision: 1100,
    };
    const listener = listenerSummary(path.listeners);
    const cloudfw = cloudFirewallSummary(path.cloudFirewallPolicies || []);
    const entryKey = assetDataAttributes(path.asset);

    return `
      <div class="network-flow-scroll">
        <svg class="network-flow-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Network exposure topology">
          <defs>
            <marker id="${markerID}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z"></path>
            </marker>
          </defs>
          ${flowLaneLabels([
            [x.internet, "Internet"],
            [x.cloudfw, "CloudFW"],
            [x.entry, "Public Entry"],
            [x.listener, "Listener"],
            [x.compute, "Backend ECS"],
            [x.policy, "Security Group"],
            [x.decision, "Ingress Policy"],
          ])}
          ${flowLink(x.internet + nodeWidth, centerY, x.cloudfw, centerY, markerID, cloudfw.tone)}
          ${flowLink(x.cloudfw + nodeWidth, centerY, x.entry, centerY, markerID, cloudfw.tone)}
          ${flowLink(x.entry + nodeWidth, centerY, x.listener, centerY, markerID, listener.aclOff ? "warn" : "public")}
          ${rows.map((backend, rowIndex) => {
            const y = firstY + rowIndex * rowGap;
            const groups = backend ? backend.securityGroups : [];
            const group = groups[0] || null;
            const policy = flowPolicySummary(groups);
            return `
              ${flowLink(x.listener + nodeWidth, centerY, x.compute, y, markerID, backend ? "public" : "warn")}
              ${backend ? flowLink(x.compute + nodeWidth, y, x.policy, y, markerID, group ? "public" : "warn") : ""}
              ${backend ? flowLink(x.policy + nodeWidth, y, x.decision, y, markerID, policy.tone) : ""}
              ${flowNode("compute", backend ? `ECS · ${backend.name || backend.nativeID}` : "No backend ECS captured", backend ? (backend.nativeID || backend.resourceID) : "No backend captured", x.compute, y - nodeHeight / 2, backend && backend.asset, backend ? "" : "missing")}
              ${flowNode("policy", group ? (group.name || group.nativeID || "Security Group") : "No linked security group", group ? `${group.openPolicies.length || 0}/${group.policies.length || 0} ${state.language === "zh" ? "公网开放规则" : "wide-open rules"}` : "No security group link", x.policy, y - nodeHeight / 2, group && group.asset, group ? (group.openPolicies.length ? "danger" : "") : "missing")}
              ${flowNode("decision", policy.title, policy.subtitle, x.decision, y - nodeHeight / 2, null, policy.tone)}
            `;
          }).join("")}
          ${flowNode("internet", "Internet", state.language === "zh" ? "公网访问来源" : "public source", x.internet, centerY - nodeHeight / 2, null, "public")}
          ${flowNode("cloudfw", cloudfw.title, cloudfw.subtitle, x.cloudfw, centerY - nodeHeight / 2, cloudfw.asset, cloudfw.tone)}
          ${flowNode("entry", `${path.type} · ${path.name}`, path.address || path.nativeID || path.resourceID, x.entry, centerY - nodeHeight / 2, path.asset, "entry", entryKey)}
          ${flowNode("listener", listener.title, listener.subtitle, x.listener, centerY - nodeHeight / 2, null, listener.aclOff ? "warn" : "")}
        </svg>
      </div>
      ${hiddenBackends ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hiddenBackends)} 个后端 ECS 已折叠。` : `${number(hiddenBackends)} backend ECS nodes are folded.`}</p>` : ""}
    `;
  }

  function flowLaneLabels(items) {
    return items.map(([x, label]) => `
      <text class="flow-lane-label" x="${x}" y="32">${escapeHTML(localPhrase(label))}</text>
    `).join("");
  }

  function flowLink(sourceX, sourceY, targetX, targetY, markerID, tone) {
    const mid = Math.max(38, Math.abs(targetX - sourceX) * 0.42);
    return `<path class="flow-link ${escapeHTML(tone || "")}" marker-end="url(#${markerID})" d="M ${sourceX} ${sourceY} C ${sourceX + mid} ${sourceY}, ${targetX - mid} ${targetY}, ${targetX} ${targetY}"></path>`;
  }

  function flowNode(kind, title, subtitle, x, y, asset, tone, precomputedAttrs) {
    const attrs = precomputedAttrs || assetDataAttributes(asset);
    return `
      <g class="flow-node ${escapeHTML(kind || "")} ${escapeHTML(tone || "")}"${attrs}>
        <title>${escapeHTML(`${title || ""} ${subtitle || ""}`.trim())}</title>
        <rect x="${x}" y="${y}" width="150" height="58" rx="14"></rect>
        <text class="flow-node-title" x="${x + 12}" y="${y + 23}">${escapeHTML(shortFlowLabel(title))}</text>
        <text class="flow-node-subtitle" x="${x + 12}" y="${y + 42}">${escapeHTML(shortFlowLabel(subtitle, 22))}</text>
      </g>
    `;
  }

  function cloudFirewallSummary(policies) {
    if (!policies.length) {
      return {
        title: "CloudFW",
        subtitle: state.language === "zh" ? "未采集入向策略" : "No inbound policy",
        tone: "warn",
        asset: null,
      };
    }
    const allow = policies.filter((policy) => policy.open).length;
    const drop = policies.filter((policy) => policy.drop).length;
    const first = policies[0];
    if (allow) {
      return {
        title: "CloudFW allow",
        subtitle: state.language === "zh" ? `${number(allow)} 条入向放行` : `${number(allow)} inbound allow`,
        tone: "danger",
        asset: first.asset,
      };
    }
    if (drop) {
      return {
        title: "CloudFW drop",
        subtitle: state.language === "zh" ? `${number(drop)} 条入向阻断` : `${number(drop)} inbound drop`,
        tone: "",
        asset: first.asset,
      };
    }
    return {
      title: "CloudFW scoped",
      subtitle: state.language === "zh" ? `${number(policies.length)} 条入向策略` : `${number(policies.length)} inbound policies`,
      tone: "",
      asset: first.asset,
    };
  }

  function listenerSummary(listeners) {
    if (!listeners.length) {
      return {
        title: "Listener",
        subtitle: state.language === "zh" ? "未采集监听" : "No listener captured",
        aclOff: false,
      };
    }
    const first = listeners[0];
    const aclOff = listeners.some((listener) => listener.aclOff);
    const title = `${first.protocol || "tcp"}:${first.port || "*"}`;
    const aclText = state.language === "zh"
      ? (aclOff ? "存在 ACL 未开启" : "ACL 已开启")
      : (aclOff ? "ACL off" : "ACL on");
    const hidden = Math.max(0, listeners.length - 1);
    return {
      title,
      subtitle: hidden ? `${aclText} · +${number(hidden)}` : aclText,
      aclOff,
    };
  }

  function flowPolicySummary(groups) {
    if (!groups.length) {
      return {
        title: "No linked security group",
        subtitle: state.language === "zh" ? "无法验证入站策略" : "Cannot verify ingress",
        tone: "warn",
      };
    }
    const policyCount = groups.reduce((total, group) => total + group.policies.length, 0);
    const openCount = groups.reduce((total, group) => total + group.openPolicies.length, 0);
    if (openCount) {
      return {
        title: "Internet open",
        subtitle: state.language === "zh" ? `${number(openCount)} 条 0.0.0.0/0 入站` : `${number(openCount)} wide-open ingress`,
        tone: "danger",
      };
    }
    return {
      title: "Inbound restricted",
      subtitle: state.language === "zh" ? `${number(policyCount)} 条规则已检查` : `${number(policyCount)} rules checked`,
      tone: "",
    };
  }

  function openPolicyCountForPath(path) {
    if (path.openPolicyCount !== undefined) {
      return numberValue(path.openPolicyCount);
    }
    const securityGroupOpen = path.backends.reduce((total, backend) => (
      total + backend.securityGroups.reduce((groupTotal, group) => groupTotal + group.openPolicies.length, 0)
    ), 0);
    const cloudFirewallOpen = (path.cloudFirewallPolicies || []).filter((policy) => policy.open).length;
    return securityGroupOpen + cloudFirewallOpen;
  }

  function assetDataAttributes(asset) {
    if (!asset) {
      return "";
    }
    const key = cacheItem("asset", asset);
    const label = state.language === "zh" ? "查看资产详情" : "Open asset details";
    return ` data-key="${escapeHTML(key)}" role="button" tabindex="0" aria-label="${escapeHTML(label)}"`;
  }

  function shortFlowLabel(value, maxLength) {
    const text = stringValue(value);
    const limit = maxLength || 18;
    return text.length > limit ? `${text.slice(0, limit - 1)}...` : text;
  }

  function exposurePathMap(exposure) {
    if (!exposure.paths.length) {
      return `<div class="empty-state">No load balancer paths available.</div>`;
    }
    const morePaths = Math.max(0, exposure.paths.length - 8);
    return `
      <div class="exposure-map">
        ${exposure.paths.slice(0, 8).map((path) => exposurePath(path)).join("")}
      </div>
      ${morePaths ? `<p class="muted">${state.language === "zh" ? `另有 ${number(morePaths)} 条公网入口链路未展示。` : `${number(morePaths)} more public entry paths are hidden.`}</p>` : ""}
    `;
  }

  function exposurePath(path) {
    const listenerPreview = path.listeners.slice(0, 4).map((listener) => {
      const acl = state.language === "zh"
        ? (listener.aclOff ? "ACL 未开启" : "ACL 已开启")
        : (listener.aclOff ? "ACL off" : "ACL on");
      return `<span class="rule-chip ${listener.aclOff ? "danger" : ""}">${escapeHTML(listener.protocol || "tcp")}:${escapeHTML(listener.port || "*")} · ${escapeHTML(acl)}</span>`;
    }).join("");
    const hiddenListeners = Math.max(0, path.listeners.length - 4);
    const backendRows = path.backends.length
      ? path.backends.slice(0, 5).map((backend) => exposureBackendRow(backend)).join("")
      : `<div class="hop-row missing"><span class="path-arrow">→</span><div class="path-node muted-node"><span class="path-kicker">Compute</span><strong>Backend missing</strong><p>No backend captured</p></div></div>`;
    const hiddenBackends = Math.max(0, path.backends.length - 5);

    return `
      <article class="exposure-path ${path.hasOpenPolicy ? "danger" : ""}">
        <div class="path-node entry-node" ${assetDataAttributes(path.asset)}>
          <span class="path-kicker">Entry</span>
          <strong>${escapeHTML(path.type)} · ${escapeHTML(path.name)}</strong>
          <code>${escapeHTML(path.address || path.nativeID)}</code>
          <div class="chips">
            ${chip(path.isPublic ? "Public" : "Private")}
            ${chip(path.region || "global")}
            ${chip("listeners", path.listeners.length)}
            ${chip("backends", path.backends.length)}
            ${(path.cloudFirewallPolicies || []).length ? chip("CloudFW", path.cloudFirewallPolicies.length) : ""}
          </div>
          <div class="listener-strip">${listenerPreview}${hiddenListeners ? `<span class="rule-chip">+${number(hiddenListeners)}</span>` : ""}</div>
        </div>
        <div class="hop-list">
          ${backendRows}
          ${hiddenBackends ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hiddenBackends)} 个后端未展示。` : `${number(hiddenBackends)} more backends are hidden.`}</p>` : ""}
        </div>
      </article>
    `;
  }

  function exposureBackendRow(backend) {
    const groups = backend.securityGroups.length
      ? backend.securityGroups.slice(0, 4).map((group) => securityGroupPolicyNode(group)).join("")
      : `<div class="path-node muted-node"><span class="path-kicker">Policy</span><strong>No security group link</strong><p>No security group policies linked</p></div>`;
    const hiddenGroups = Math.max(0, backend.securityGroups.length - 4);
    return `
      <div class="hop-row">
        <span class="path-arrow">→</span>
        <div class="path-node compute-node" ${assetDataAttributes(backend.asset)}>
          <span class="path-kicker">Compute</span>
          <strong>ECS · ${escapeHTML(backend.name || backend.nativeID)}</strong>
          <code>${escapeHTML(backend.nativeID || backend.resourceID)}</code>
          <div class="chips">
            ${backend.port ? chip("port", backend.port) : ""}
            ${backend.weight !== "" ? chip("weight", backend.weight) : ""}
          </div>
        </div>
        <span class="path-arrow">→</span>
        <div class="policy-stack">
          ${groups}
          ${hiddenGroups ? `<span class="muted">${state.language === "zh" ? `另有 ${number(hiddenGroups)} 个安全组` : `${number(hiddenGroups)} more groups`}</span>` : ""}
        </div>
      </div>
    `;
  }

  function securityGroupPolicyNode(group) {
    const policies = group.openPolicies.length ? group.openPolicies : group.policies.slice(0, 2);
    const policyText = policies.length
      ? policies.slice(0, 3).map((policy) => `<span class="rule-chip ${policy.open ? "danger" : ""}">${escapeHTML(policy.source || "*")} · ${escapeHTML(policy.protocol || "ALL")}:${escapeHTML(policy.port || "*")}</span>`).join("")
      : `<span class="muted">${state.language === "zh" ? "未发现公网开放入站规则" : "No wide-open ingress"}</span>`;
    return `
      <div class="path-node policy-node ${group.openPolicies.length ? "danger" : ""}" ${assetDataAttributes(group.asset)}>
        <span class="path-kicker">Policy</span>
        <strong>${escapeHTML(group.name || group.nativeID)}</strong>
        <code>${escapeHTML(group.nativeID || group.resourceID)}</code>
        <div class="chips">
          ${chip("Rule", group.policies.length)}
          ${group.openPolicies.length ? chip("wide open", group.openPolicies.length) : ""}
        </div>
        <div class="policy-rules">${policyText}</div>
      </div>
    `;
  }

  function buildDataExposureModel(assets) {
    const dataAssets = assets.filter((asset) => dataAssetType(asset.resource_type));
    const exposures = dataAssets
      .map((asset) => dataExposureSummary(asset))
      .filter((item) => item.signals.length)
      .sort((left, right) => riskRank(right.severity) - riskRank(left.severity) || Number(right.internetFacing) - Number(left.internetFacing));

    return {
      dataAssets: dataAssets.map((asset) => ({ asset, type: dataAssetType(asset.resource_type) })),
      dataAssetCount: dataAssets.length,
      exposedCount: exposures.length,
      internetFacingCount: exposures.filter((item) => item.internetFacing).length,
      wideACLCount: exposures.filter((item) => item.wideACL).length,
      exposures,
    };
  }

  function dataExposureSummary(asset) {
    const type = dataAssetType(asset.resource_type);
    if (type === "OSS") {
      return ossExposureSummary(asset);
    }
    if (type === "SLS") {
      return slsExposureSummary(asset);
    }
    if (type) {
      return databaseExposureSummary(asset, type);
    }
    return dataExposureItem(asset, type || "Data", [], "info");
  }

  function ossExposureSummary(asset) {
    const attributes = assetAttributes(asset);
    const bucket = firstObject([
      attributes.BucketInfo,
      attributes.bucketInfo,
      attributes.Bucket,
      attributes.bucket,
      attributes,
    ]);
    const acl = lower(firstNonEmpty([
      valueFrom(bucket, ["ACL", "Acl", "acl"], ""),
      valueFrom(attributes, ["ACL", "Acl", "acl"], ""),
    ]));
    const blockPublic = truthy(firstNonEmpty([
      valueFrom(bucket, ["BlockPublicAccess", "blockPublicAccess"], ""),
      valueFrom(attributes, ["BlockPublicAccess", "blockPublicAccess"], ""),
    ]));
    const publicACL = ["public-read", "public-read-write"].includes(acl);
    const policyStatus = firstObject([
      attributes.BucketPolicyStatus,
      attributes.bucketPolicyStatus,
      bucket.BucketPolicyStatus,
      bucket.bucketPolicyStatus,
    ]);
    const policyStatusPublic = valueFrom(policyStatus, ["IsPublic", "isPublic"], undefined);
    const publicPolicy = publicBucketPolicySummary(firstDefined([
      valueFrom(attributes, ["BucketPolicy", "bucketPolicy"], ""),
      valueFrom(bucket, ["BucketPolicy", "bucketPolicy"], ""),
      valueFrom(attributes, ["Policy", "policy"], ""),
    ]), policyStatusPublic);
    const effectivePublicACL = publicACL && !blockPublic;
    const effectivePublicPolicy = publicPolicy.public && !blockPublic;
    const signals = [];
    if (effectivePublicACL) {
      signals.push({ label: acl === "public-read-write" ? "public write" : "public read", tone: acl === "public-read-write" ? "danger" : "warn" });
    }
    if (effectivePublicPolicy) {
      signals.push({ label: publicPolicy.write ? "public policy write" : "public policy", tone: publicPolicy.write ? "danger" : "warn" });
    }
    const severity = publicPolicy.write || acl === "public-read-write" ? "critical" : (signals.length ? "high" : "info");
    return dataExposureItem(asset, "OSS", signals, severity, {
      internetFacing: signals.length > 0,
      publicEndpoint: signals.length > 0,
      wideACL: publicACL,
      summary: blockPublic && publicACL
        ? "Bucket has public ACL but BlockPublicAccess is enabled, so it is not counted as effective public exposure."
        : "",
    });
  }

  function slsExposureSummary(asset) {
    const attributes = assetAttributes(asset);
    const policyStatus = firstObject([
      attributes.PolicyStatus,
      attributes.policyStatus,
      attributes.ProjectPolicy,
      attributes.projectPolicy,
    ]);
    const policy = publicProjectPolicySummary(firstDefined([
      valueFrom(policyStatus, ["body", "Body"], ""),
      valueFrom(attributes, ["Policy", "policy"], ""),
    ]));
    const signals = [];
    if (policy.public) {
      signals.push({ label: policy.write ? "public policy write" : "public policy", tone: policy.write ? "danger" : "warn" });
    }
    const severity = policy.write ? "critical" : (signals.length ? "high" : "info");
    return dataExposureItem(asset, "SLS", signals, severity, {
      internetFacing: signals.length > 0,
      publicEndpoint: signals.length > 0,
      wideACL: false,
    });
  }

  function publicProjectPolicySummary(value) {
    const statements = policyStatements(value);
    const publicStatements = statements.filter((statement) => {
      const effect = lower(valueFrom(statement, ["Effect", "effect"], "allow"));
      return effect === "allow" && statementAllowsPublicPrincipal(statement) && !valueFrom(statement, ["Condition", "condition"], null);
    });
    const actions = publicStatements.flatMap((statement) => policyActions(statement));
    return {
      public: publicStatements.length > 0,
      read: actions.length === 0 || actions.some((action) => /(\*|:get|:list|:read|:query)/i.test(action)),
      write: actions.some((action) => /(\*|:put|:post|:delete|:create|:set)/i.test(action)),
    };
  }

  function databaseExposureSummary(asset, type) {
    const attributes = assetAttributes(asset);
    const publicEndpoint = hasPublicDataEndpoint(attributes);
    const accessLists = collectAccessListEntries(attributes);
    const wideACL = accessLists.some((entry) => isAnySource(entry));
    const signals = [];
    if (publicEndpoint) {
      signals.push({ label: "public endpoint", tone: "warn" });
    }
    if (wideACL) {
      signals.push({ label: "wide whitelist", tone: publicEndpoint ? "danger" : "warn" });
    }
    const severity = publicEndpoint && wideACL ? "critical" : (publicEndpoint || wideACL ? "high" : "info");
    return dataExposureItem(asset, type, signals, severity, {
      internetFacing: publicEndpoint,
      publicEndpoint,
      wideACL,
      summary: publicEndpoint
        ? "Public endpoint exists; whitelist controls who can reach it."
        : (wideACL ? "Whitelist is broad, but no public endpoint was found in collected properties." : ""),
    });
  }

  function dataExposureItem(asset, type, signals, severity, extra) {
    return {
      ...(extra || {}),
      asset,
      type,
      key: asset.resource_id || asset.id,
      name: asset.name || nativeID(asset.resource_id) || asset.id,
      resourceID: asset.resource_id || asset.id,
      region: asset.region || "global",
      severity,
      signals,
      internetFacing: Boolean(extra && extra.internetFacing),
      publicEndpoint: Boolean(extra && extra.publicEndpoint),
      wideACL: Boolean(extra && extra.wideACL),
      summary: stringValue(extra && extra.summary),
    };
  }

  function dataExposurePanel(model) {
    if (!model.exposures.length) {
      return `<div class="empty-state">No data exposure detected from current asset properties.</div>`;
    }
    const hidden = Math.max(0, model.exposures.length - 8);
    return `
      <div class="exposure-list">
        ${model.exposures.slice(0, 8).map((item) => dataExposureCard(item)).join("")}
      </div>
      ${hidden ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hidden)} 个数据暴露项未展示。` : `${number(hidden)} more data exposure items are hidden.`}</p>` : ""}
    `;
  }

  function dataExposureCard(item) {
    const exposureLabel = state.language === "zh"
      ? (item.internetFacing ? "公网可达" : "访问控制")
      : (item.internetFacing ? "internet-facing" : "access control");
    return `
      <div class="path-node data-node ${riskRank(item.severity) >= riskRank("high") ? "danger" : ""}" ${assetDataAttributes(item.asset)}>
        <span class="path-kicker">${escapeHTML(item.type)} · ${escapeHTML(exposureLabel)}</span>
        <strong>${escapeHTML(item.name)}</strong>
        <code>${escapeHTML(nativeID(item.resourceID) || item.resourceID)}</code>
        <div class="chips">
          ${chip(item.region || "global")}
          ${severityChip(item.severity)}
          ${item.signals.map((signal) => `<span class="rule-chip ${escapeHTML(signal.tone || "")}">${escapeHTML(localPhrase(signal.label))}</span>`).join("")}
        </div>
        ${item.summary ? `<p class="muted">${escapeHTML(localPhrase(item.summary))}</p>` : ""}
      </div>
    `;
  }

  function buildIdentityExposureModel(assets, dataExposure) {
    const identities = assets
      .filter((asset) => isRAMUser(asset.resource_type))
      .map((asset) => identityControlSummary(asset))
      .filter((entry) => entry.activeKeyCount || entry.services.length);
    const dataServices = new Set((dataExposure.dataAssets || []).map((item) => dataServiceForType(item.type)).filter(Boolean));
    const riskEntries = identities
      .map((entry) => ({
        ...entry,
        riskyServices: entry.services.filter((service) =>
          entry.activeKeyCount > 0 &&
          !entry.sourceRestricted &&
          !service.sourceRestricted &&
          serviceMatchesDataServices(service.name, dataServices)
        ),
      }))
      .filter((entry) => entry.riskyServices.length)
      .sort((left, right) => right.activeKeyCount - left.activeKeyCount || right.riskyServices.length - left.riskyServices.length);
    const controlEdges = [];
    const targets = (dataExposure.exposures.length ? dataExposure.exposures : dataExposure.dataAssets.map((item) => dataExposureItem(item.asset, item.type, [], "info")))
      .filter((item) => dataServiceForType(item.type));
    riskEntries.slice(0, 8).forEach((entry) => {
      targets
        .filter((target) => entry.riskyServices.some((service) => serviceMatchesDataTarget(service, target)))
        .slice(0, 4)
        .forEach((target) => {
          const service = entry.riskyServices.find((item) => serviceMatchesDataTarget(item, target));
          controlEdges.push({ identity: entry, data: target, service, mode: credentialPathMode(service, target) });
        });
    });
    const dataPlanePathCount = controlEdges.filter((edge) => edge.mode === "data-plane access").length;
    const managementPathCount = controlEdges.filter((edge) => edge.mode !== "data-plane access").length;

    return {
      entries: identities,
      riskEntries,
      activeRiskCount: riskEntries.length,
      unrestrictedRiskCount: riskEntries.length,
      activeKeyCount: identities.reduce((total, entry) => total + entry.activeKeyCount, 0),
      dataServices: Array.from(dataServices),
      controlEdges,
      dataPlanePathCount,
      managementPathCount,
    };
  }

  function identityControlSummary(asset) {
    const attributes = assetAttributes(asset);
    const accessKeys = accessKeySummaries(attributes);
    const explicitActive = truthy(valueFrom(attributes, ["ExistActiveAccessKey", "existActiveAccessKey"], false));
    const activeKeyCount = Math.max(accessKeys.filter((key) => key.active).length, explicitActive ? 1 : 0);
    const inactiveKeyCount = accessKeys.filter((key) => key.inactive).length;
    const policies = policySummaries(attributes);
    const services = policyDataServices(policies);
    const sourceRestricted = policies.some((policy) => policy.sourceGuard);
    const policyDocumentCount = policies.filter((policy) => policy.documentCollected).length;
    const sourceConditions = sourceConditionsFromPolicies(policies);
    const sourceACLStatus = sourceRestricted ? "restricted" : (policyDocumentCount ? "unrestricted" : "not_collected");
    return {
      asset,
      key: asset.resource_id || asset.id,
      name: asset.name || nativeID(asset.resource_id) || asset.id,
      resourceID: asset.resource_id || asset.id,
      activeKeyCount,
      inactiveKeyCount,
      activeAccessKeys: accessKeys.filter((key) => key.active && key.id).map((key) => key.id),
      policies,
      services,
      sourceRestricted,
      sourceACLStatus,
      sourceConditions,
      policyDocumentCount,
    };
  }

  function identityExposurePanel(model) {
    if (!model.riskEntries.length) {
      return `<div class="empty-state">No unrestricted active access-key path detected.</div>`;
    }
    const hidden = Math.max(0, model.riskEntries.length - 8);
    return `
      <div class="exposure-list">
        ${model.riskEntries.slice(0, 8).map((entry) => identityControlCard(entry)).join("")}
      </div>
      ${hidden ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hidden)} 个 RAM 用户未展示。` : `${number(hidden)} more RAM users are hidden.`}</p>` : ""}
    `;
  }

  function identityControlCard(entry) {
    return `
      <div class="path-node identity-node danger" ${assetDataAttributes(entry.asset)}>
        <span class="path-kicker">${escapeHTML(state.language === "zh" ? "RAM 用户 · 凭证路径" : "RAM User · credential path")}</span>
        <strong>${escapeHTML(entry.name)}</strong>
        <code>${escapeHTML(nativeID(entry.resourceID) || entry.resourceID)}</code>
        <div class="chips">
          ${chip("active AK", entry.activeKeyCount)}
          ${entry.inactiveKeyCount ? chip("inactive AK", entry.inactiveKeyCount) : ""}
          ${chip(entry.sourceRestricted ? "source restricted" : "source unrestricted")}
          ${chip("policies", entry.policies.length)}
        </div>
        <div class="policy-rules">
          ${entry.riskyServices.slice(0, 6).map((service) => `<span class="rule-chip ${service.level === "read access" ? "" : "danger"}">${escapeHTML(service.name)} · ${escapeHTML(localPhrase(service.pathKind || service.level))}</span>`).join("")}
        </div>
        ${sourceACLPanel(identitySourceACLEvidence(entry), [entry.sourceACLStatus === "not_collected" ? "source_acl_not_collected" : (entry.sourceRestricted ? "source_restricted" : "source_unrestricted")])}
      </div>
    `;
  }

  function riskPathPanel(riskPaths, pathTypes, fallback, emptyMessage) {
    if (!riskPaths.available) {
      return fallback();
    }
    const allowed = new Set(pathTypes);
    const useGroups = pathTypes.some((type) => type.startsWith("credential_"));
    const groups = useGroups ? (riskPaths.groups || []).filter((group) => allowed.has(group.pathType)) : [];
    if (groups.length) {
      const hiddenGroups = Math.max(0, groups.length - 8);
      return `
        <div class="exposure-list">
          ${groups.slice(0, 8).map((group) => riskPathGroupCard(group)).join("")}
        </div>
        ${hiddenGroups ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hiddenGroups)} 个聚合风险路径未展示。` : `${number(hiddenGroups)} more grouped risk paths are hidden.`}</p>` : ""}
      `;
    }
    const paths = (riskPaths.paths || []).filter((path) => allowed.has(path.pathType));
    if (!paths.length) {
      return `<div class="empty-state">${escapeHTML(emptyMessage)}</div>`;
    }
    const hidden = Math.max(0, paths.length - 8);
    return `
      <div class="exposure-list">
        ${paths.slice(0, 8).map((path) => riskPathCard(path)).join("")}
      </div>
      ${hidden ? `<p class="muted">${state.language === "zh" ? `另有 ${number(hidden)} 条后端风险路径未展示。` : `${number(hidden)} more backend risk paths are hidden.`}</p>` : ""}
    `;
  }

  function credentialPathPanel(riskPaths, fallbackModel) {
    if (!riskPaths.available) {
      return identityExposurePanel(fallbackModel);
    }
    const dataGroups = (riskPaths.groups || []).filter((group) => group.pathType === "credential_data_access");
    const controlGroups = (riskPaths.groups || []).filter((group) => group.pathType === "credential_control_plane_exposure");
    const dataPaths = (riskPaths.paths || []).filter((path) => path.pathType === "credential_data_access");
    const controlPaths = (riskPaths.paths || []).filter((path) => path.pathType === "credential_control_plane_exposure");
    if (!dataGroups.length && !controlGroups.length && !dataPaths.length && !controlPaths.length) {
      return `<div class="empty-state">No unrestricted active access-key path detected.</div>`;
    }
    return `
      <div class="credential-path-layout">
        ${credentialPathColumn(
          "Data-plane credential access",
          "AK can call data APIs such as OSS or SLS directly when policy and target resource match.",
          dataGroups,
          dataPaths,
          "No data-plane credential path detected."
        )}
        ${credentialPathColumn(
          "Control-plane credential risk",
          "AK can view or change database/cache exposure, but cannot directly read data without service credentials.",
          controlGroups,
          controlPaths,
          "No control-plane credential risk detected."
        )}
      </div>
    `;
  }

  function credentialPathColumn(title, description, groups, paths, emptyMessage) {
    const items = groups.length ? groups : paths;
    const totalTargets = groups.length
      ? groups.reduce((total, group) => total + numberValue(group.targetCount || group.targets.length), 0)
      : paths.length;
    return `
      <section class="credential-path-column">
        <div class="credential-column-head">
          <div>
            <h3>${escapeHTML(localPhrase(title))}</h3>
            <p>${escapeHTML(localPhrase(description))}</p>
          </div>
          <span class="chip">${number(totalTargets)} ${escapeHTML(localPhrase("Affected targets"))}</span>
        </div>
        ${items.length ? `
          <div class="credential-card-list">
            ${items.slice(0, 5).map((item) => credentialPathCard(item)).join("")}
          </div>
          ${Math.max(0, items.length - 5) ? `<p class="muted">${state.language === "zh" ? `另有 ${number(items.length - 5)} 个 AK 权限路径分组未展示。` : `${number(items.length - 5)} more credential path groups are hidden.`}</p>` : ""}
        ` : `<div class="empty-state">${escapeHTML(emptyMessage)}</div>`}
      </section>
    `;
  }

  function credentialPathCard(item) {
    const targets = item.targets && item.targets.length ? item.targets : [item.target].filter(Boolean);
    const targetCount = numberValue(item.targetCount || targets.length);
    const source = item.source;
    const evidence = item.evidence || {};
    const status = sourceACLStatus(evidence, item.signals);
    const tone = status === "not_collected" ? "warn" : (riskRank(item.severity) >= riskRank("high") ? "danger" : "");
    const permission = credentialPermissionLabel(evidence, item.signals);
    const policyNames = normalizeList(valueFrom(evidence, ["policy_names", "policyNames"], []))
      .map((name) => stringValue(name))
      .filter(Boolean);
    const resourcePatterns = normalizeList(valueFrom(evidence, ["resource_patterns", "resourcePatterns"], []))
      .map((pattern) => stringValue(pattern))
      .filter(Boolean);
    return `
      <article class="credential-card ${escapeHTML(tone)}">
        <div class="credential-flow">
          ${credentialFlowNode("identity", source ? (source.name || nativeID(source.resource_id) || source.resource_id) : "Cloud control plane", source ? (source.resource_type || "RAM User") : "Identity", source)}
          <span class="credential-arrow">→</span>
          ${credentialFlowNode("permission", permission.title, permission.subtitle, null, tone)}
          <span class="credential-arrow">→</span>
          ${credentialFlowNode("target", `${item.service || "Service"} · ${number(targetCount)}`, state.language === "zh" ? "目标资源" : "targets", targets[0], tone)}
        </div>
        <div class="chips credential-chips">
          ${severityChip(item.severity)}
          ${chip(localPhrase(status === "not_collected" ? "needs verification" : "confirmed"))}
          ${chip(localPhrase(sourceACLStatusLabel(status)))}
          ${chip(localPhrase("active AK"), numberValue(valueFrom(evidence, ["active_key_count", "activeKeyCount"], 0)))}
          ${chip(localPhrase("Policy documents"), numberValue(valueFrom(evidence, ["policy_document_count", "policyDocumentCount"], 0)))}
        </div>
        ${policyNames.length || resourcePatterns.length ? `
          <div class="credential-meta">
            ${policyNames.length ? `<p><span>${escapeHTML(localPhrase("Policy"))}</span>${policyNames.slice(0, 3).map((name) => `<code>${escapeHTML(name)}</code>`).join("")}</p>` : ""}
            ${resourcePatterns.length ? `<p><span>${escapeHTML(localPhrase("Resource scope"))}</span>${resourcePatterns.slice(0, 3).map((pattern) => `<code>${escapeHTML(pattern)}</code>`).join("")}</p>` : ""}
          </div>
        ` : ""}
        <div class="policy-rules credential-targets">
          ${targets.slice(0, 6).map((target) => `<span class="rule-chip"${assetDataAttributes(target)}>${escapeHTML(target.name || nativeID(target.resource_id) || target.resource_id || target.id || "target")}</span>`).join("")}
          ${targetCount > Math.min(6, targets.length) ? `<span class="rule-chip">+${number(targetCount - Math.min(6, targets.length))}</span>` : ""}
        </div>
        ${sourceACLPanel(evidence, item.signals)}
      </article>
    `;
  }

  function credentialFlowNode(kind, title, subtitle, asset, tone) {
    const attrs = kind === "identity" || kind === "target" ? assetDataAttributes(asset) : "";
    return `
      <div class="credential-flow-node ${escapeHTML(kind || "")} ${escapeHTML(tone || "")}"${attrs}>
        <span>${escapeHTML(localPhrase(kind === "permission" ? "Permission" : kind))}</span>
        <strong>${escapeHTML(title || "")}</strong>
        <code>${escapeHTML(localPhrase(subtitle || ""))}</code>
      </div>
    `;
  }

  function credentialPermissionLabel(evidence, signals) {
    const level = localPhrase(stringValue(valueFrom(evidence, ["permission_level", "permissionLevel"], "")) || "permission");
    const kind = localPhrase(stringValue(valueFrom(evidence, ["path_kind", "pathKind"], "")) || (signals || []).find((signal) => signal.includes("plane")) || "");
    return {
      title: level,
      subtitle: kind,
    };
  }

  function riskPathGroupCard(group) {
    const source = group.source;
    const sourceText = source
      ? `${source.resource_type || "Identity"} · ${source.name || nativeID(source.resource_id) || source.resource_id || source.id}`
      : (group.pathType === "anonymous_public_data_access" ? "Internet / anonymous" : "Cloud control plane");
    const targets = group.targets || [];
    const targetPreview = targets.slice(0, 4).map((target) => `<span class="rule-chip">${escapeHTML(target.name || nativeID(target.resource_id) || target.resource_id || target.id)}</span>`).join("");
    const hidden = Math.max(0, numberValue(group.targetCount) - targets.slice(0, 4).length);
    return `
      <div class="path-node identity-node ${riskRank(group.severity) >= riskRank("high") ? "danger" : ""}">
        <span class="path-kicker">${escapeHTML(pathLabel(group.pathType))}</span>
        <strong>${escapeHTML(group.service || "Service")} · ${number(group.targetCount || targets.length)} ${escapeHTML(state.language === "zh" ? "个目标资源" : "targets")}</strong>
        <code>${escapeHTML(sourceText)}</code>
        <div class="chips">
          ${severityChip(group.severity)}
          ${chip(group.region || "global")}
          ${chip("targets", group.targetCount || targets.length)}
        </div>
        <div class="policy-rules">
          ${targetPreview}${hidden ? `<span class="rule-chip">+${number(hidden)}</span>` : ""}
        </div>
        <div class="policy-rules">
          ${(group.signals || []).slice(0, 5).map((signal) => `<span class="rule-chip">${escapeHTML(localPhrase(signalLabel(signal)))}</span>`).join("")}
        </div>
        ${sourceACLPanel(group.evidence, group.signals)}
      </div>
    `;
  }

  function riskPathCard(path) {
    const source = path.source;
    const target = path.target || {};
    const title = target.name || nativeID(target.resource_id) || target.resource_id || target.id || path.service;
    const sourceText = source
      ? `${source.resource_type || "Identity"} · ${source.name || nativeID(source.resource_id) || source.resource_id || source.id}`
      : (path.pathType === "anonymous_public_data_access" ? "Internet / anonymous" : "Cloud control plane");
    return `
      <div class="path-node data-node ${riskRank(path.severity) >= riskRank("high") ? "danger" : ""}">
        <span class="path-kicker">${escapeHTML(pathLabel(path.pathType))}</span>
        <strong>${escapeHTML(path.service || target.resource_type || "Data")} · ${escapeHTML(title)}</strong>
        <code>${escapeHTML(nativeID(target.resource_id) || target.resource_id || target.id || "")}</code>
        <div class="chips">
          ${severityChip(path.severity)}
          ${chip(path.region || "global")}
          ${chip(sourceText)}
        </div>
        <div class="policy-rules">
          ${(path.signals || []).slice(0, 6).map((signal) => `<span class="rule-chip">${escapeHTML(localPhrase(signalLabel(signal)))}</span>`).join("")}
        </div>
        ${sourceACLPanel(path.evidence, path.signals)}
      </div>
    `;
  }

  function identitySourceACLEvidence(entry) {
    return {
      active_key_count: entry.activeKeyCount,
      active_access_keys: entry.activeAccessKeys || [],
      inactive_key_count: entry.inactiveKeyCount,
      policy_count: entry.policies.length,
      policy_document_count: entry.policyDocumentCount,
      policy_documents_collected: entry.policyDocumentCount > 0,
      policy_names: entry.policies.map((policy) => policy.name).filter(Boolean),
      source_acl_status: entry.sourceACLStatus,
      source_restricted: entry.sourceRestricted,
      source_conditions: entry.sourceConditions || [],
    };
  }

  function sourceACLPanel(evidence, signals) {
    const data = evidence && typeof evidence === "object" ? evidence : {};
    const hasCredentialSignal = (signals || []).some((signal) => ["active_ak", "source_unrestricted", "source_acl_not_collected"].includes(signal));
    const status = sourceACLStatus(data, signals);
    if (!hasCredentialSignal && !status) {
      return "";
    }
    const activeKeys = normalizeList(valueFrom(data, ["active_access_keys", "activeAccessKeys"], []))
      .map((item) => stringValue(item))
      .filter(Boolean);
    const conditions = normalizeSourceConditions(valueFrom(data, ["source_conditions", "sourceConditions"], []));
    const docsCollected = truthy(valueFrom(data, ["policy_documents_collected", "policyDocumentsCollected"], false));
    const docCount = numberValue(valueFrom(data, ["policy_document_count", "policyDocumentCount"], 0));
    const policyNames = normalizeList(valueFrom(data, ["policy_names", "policyNames"], []))
      .map((item) => stringValue(item))
      .filter(Boolean);
    return `
      <div class="acl-evidence">
        <div class="acl-evidence-head">
          <span class="meta-label">${escapeHTML(localPhrase("AK Source ACL"))}</span>
          <span class="rule-chip ${sourceACLStatusTone(status)}">${escapeHTML(sourceACLStatusLabel(status))}</span>
        </div>
        <div class="chips">
          ${chip("active AK", numberValue(valueFrom(data, ["active_key_count", "activeKeyCount"], activeKeys.length)))}
          ${activeKeys.slice(0, 4).map((key) => chip(key)).join("")}
          ${chip("Policy documents", docCount)}
          ${policyNames.slice(0, 3).map((name) => chip(name)).join("")}
        </div>
        ${conditions.length ? `
          <p class="meta-label">${escapeHTML(localPhrase("Source conditions"))}</p>
          <div class="policy-rules">${conditions.map((condition) => `<span class="rule-chip">${escapeHTML(condition.key)}=${escapeHTML(condition.values.join(","))}</span>`).join("")}</div>
        ` : `<p class="muted">${escapeHTML(localPhrase(docsCollected ? "No source restriction condition was collected for this credential path." : "PolicyDocument was not collected, so this path is treated as source-unknown rather than proven unrestricted."))}</p>`}
      </div>
    `;
  }

  function sourceACLStatus(evidence, signals) {
    const raw = stringValue(valueFrom(evidence, ["source_acl_status", "sourceAclStatus", "acl_status", "aclStatus"], ""));
    if (raw) {
      return raw;
    }
    if ((signals || []).includes("source_acl_not_collected")) {
      return "not_collected";
    }
    if ((signals || []).includes("source_restricted")) {
      return "restricted";
    }
    if ((signals || []).includes("source_unrestricted")) {
      return "unrestricted";
    }
    return "";
  }

  function sourceACLStatusLabel(status) {
    return {
      not_collected: localPhrase("not collected"),
      unrestricted: localPhrase("unrestricted"),
      restricted: localPhrase("restricted"),
    }[status] || localPhrase("unknown");
  }

  function sourceACLStatusTone(status) {
    if (status === "unrestricted") {
      return "danger";
    }
    if (status === "not_collected") {
      return "warn";
    }
    return "";
  }

  function normalizeSourceConditions(value) {
    const items = normalizeList(value);
    return items.map((item) => {
      const condition = item && typeof item === "object" ? item : {};
      const key = stringValue(valueFrom(condition, ["key", "name"], ""));
      const values = normalizeList(valueFrom(condition, ["values", "value"], []))
        .map((entry) => stringValue(entry))
        .filter(Boolean);
      return { key, values };
    }).filter((item) => item.key && item.values.length);
  }

  function sourceConditionsFromPolicies(policies) {
    const byKey = new Map();
    policies.forEach((policy) => {
      (policy.sourceConditions || []).forEach((condition) => {
        const values = byKey.get(condition.key) || [];
        byKey.set(condition.key, unique([...values, ...(condition.values || [])]));
      });
    });
    return Array.from(byKey.entries()).map(([key, values]) => ({ key, values }));
  }

  function sourceConditionsFromStatements(statements) {
    const keys = ["acs:SourceIp", "acs:SourceVpc", "acs:SourceVpcId", "acs:AccessId"];
    return keys.map((key) => {
      const values = statements.flatMap((statement) => conditionValuesForKey(valueFrom(statement, ["Condition", "condition"], null), key))
        .map((value) => key === "acs:AccessId" ? maskedAccessKeyID(value) : stringValue(value))
        .filter(Boolean);
      return { key, values: unique(values).slice(0, 8) };
    }).filter((condition) => condition.values.length);
  }

  function maskedAccessKeyID(value) {
    const text = String(value || "").trim();
    if (!text) {
      return "";
    }
    if (text.length <= 4) {
      return "[redacted]";
    }
    return `****${text.slice(-4)}`;
  }

  function pathLabel(pathType) {
    return {
      anonymous_public_data_access: state.language === "zh" ? "匿名公网数据访问" : "Anonymous public data access",
      credential_data_access: state.language === "zh" ? "凭证数据面访问" : "Credential data-plane access",
      credential_control_plane_exposure: state.language === "zh" ? "凭证控制面风险" : "Credential control-plane exposure",
      direct_network_exposure: state.language === "zh" ? "公网网络暴露" : "Direct network exposure",
      broad_network_acl: state.language === "zh" ? "宽松访问白名单" : "Broad access list",
    }[pathType] || pathType;
  }

  function signalLabel(signal) {
    return {
      public_write_acl: "public write",
      public_read_acl: "public read",
      public_project_policy: "public policy",
      public_policy_write: "public policy write",
      public_policy: "public policy",
      public_endpoint: "public endpoint",
      wide_whitelist: "wide whitelist",
      active_ak: "active AK",
      source_unrestricted: "source unrestricted",
      source_acl_not_collected: "source acl not collected",
    }[signal] || signal;
  }

  function relationshipCoverage(exposure, relationships, graph, dataExposure, identityExposure, riskPaths) {
    return `
      <div class="detail-list compact">
        ${detailRow("Load balancers without backend data", exposure.missingBackendCount)}
        ${detailRow("Backend ECS without security-group edge", exposure.backendsWithoutSecurityGroup)}
        ${detailRow("Listeners without ACL", exposure.aclOffCount)}
        ${detailRow("Data assets checked", dataExposure.dataAssetCount)}
        ${detailRow("Internet-facing data assets", dataExposure.internetFacingCount)}
        ${detailRow("Data assets with broad ACL", dataExposure.wideACLCount)}
        ${detailRow("RAM users with unrestricted active AK paths", identityExposure.unrestrictedRiskCount)}
        ${riskPaths.available ? detailRow("Backend risk paths", riskPaths.total) : ""}
        ${detailRow("Raw ECS-security group edges", relationships.length)}
        ${detailRow("Graph Nodes", graph.nodes.length)}
      </div>
    `;
  }

  function buildTopologyModel(assets, relationships, exposure, dataExposure, identityExposure) {
    const laneDefs = topologyLaneDefinitions();
    const edges = [];
    const connected = new Set();
    const priority = new Set();
    exposure.entries.forEach((entry) => {
      priority.add(topologyResourceKey(entry.resourceID));
      entry.backends.forEach((backend) => {
        priority.add(topologyResourceKey(backend.resourceID));
        backend.securityGroups.forEach((group) => {
          priority.add(topologyResourceKey(group.resourceID));
        });
        addTopologyEdge(edges, connected, entry.resourceID, backend.resourceID, "routes_to");
      });
    });
    dataExposure.exposures.forEach((item) => {
      priority.add(topologyAssetKey(item.asset));
    });
    identityExposure.riskEntries.forEach((entry) => {
      priority.add(topologyAssetKey(entry.asset));
    });
    identityExposure.controlEdges.forEach((edge) => {
      priority.add(topologyAssetKey(edge.identity.asset));
      priority.add(topologyAssetKey(edge.data.asset));
      addTopologyEdge(edges, connected, edge.identity.resourceID, edge.data.resourceID, "controls_data");
    });
    relationships.forEach((relationship) => {
      addTopologyEdge(edges, connected, relationship.source_resource_id, relationship.target_resource_id, relationship.relationship_type);
    });

    const lanes = laneDefs.map((definition) => {
      const laneAssets = assets
        .filter((asset) => topologyLaneKey(asset) === definition.key)
        .sort((left, right) => topologyAssetSort(left, right, connected, priority));
      const visibleAssets = laneAssets.slice(0, definition.limit);
      return {
        ...definition,
        total: laneAssets.length,
        hidden: Math.max(0, laneAssets.length - visibleAssets.length),
        nodes: visibleAssets.map((asset) => topologyNodeFromAsset(asset, definition.key)),
      };
    });
    const visibleKeys = new Set(lanes.flatMap((lane) => lane.nodes.map((node) => node.id)));
    const visibleEdges = edges
      .filter((edge) => visibleKeys.has(edge.source) && visibleKeys.has(edge.target))
      .slice(0, 90);

    return {
      assetCount: assets.length,
      edgeCount: edges.length,
      visibleNodeCount: visibleKeys.size,
      lanes,
      edges: visibleEdges,
    };
  }

  function topologyStage(topology) {
    if (!topology.visibleNodeCount) {
      return `<div class="empty-state">No graph nodes available.</div>`;
    }
    const laneWidth = 168;
    const nodeWidth = 132;
    const nodeHeight = 38;
    const laneGap = 18;
    const top = 70;
    const rowGap = 52;
    const maxRows = Math.max(1, ...topology.lanes.map((lane) => lane.nodes.length + (lane.hidden ? 1 : 0)));
    const width = topology.lanes.length * laneWidth + (topology.lanes.length - 1) * laneGap;
    const height = Math.max(360, top + maxRows * rowGap + 42);
    const positioned = new Map();
    const lanes = topology.lanes.map((lane, laneIndex) => {
      const x = laneIndex * (laneWidth + laneGap) + 14;
      const nodes = lane.nodes.map((node, nodeIndex) => {
        const positionedNode = { ...node, x, y: top + nodeIndex * rowGap, width: nodeWidth, height: nodeHeight };
        positioned.set(node.id, positionedNode);
        return positionedNode;
      });
      return { ...lane, x, nodes };
    });
    const links = topology.edges
      .map((edge) => ({ ...edge, source: positioned.get(edge.source), target: positioned.get(edge.target) }))
      .filter((edge) => edge.source && edge.target);

    return `
      <div class="topology-summary">
        ${miniStat("Collected Assets", topology.assetCount)}
        ${miniStat("Inferred Edges", topology.edgeCount)}
        ${miniStat("Visible Nodes", topology.visibleNodeCount)}
        ${miniStat("Sampled lanes", topology.lanes.filter((lane) => lane.hidden).length)}
      </div>
      <div class="topology-scroll">
        <svg class="topology-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Complete asset topology preview">
          ${lanes.map((lane) => `
            <g class="topology-lane">
              <text class="topology-lane-label" x="${lane.x}" y="26">${escapeHTML(topologyLaneLabel(lane))}</text>
              <text class="topology-lane-count" x="${lane.x}" y="45">${number(lane.total)}</text>
            </g>
          `).join("")}
          ${links.map((edge) => topologyLink(edge)).join("")}
          ${lanes.map((lane) => `
            <g>
              ${lane.nodes.map((node) => topologyNode(node)).join("")}
              ${lane.hidden ? topologyHiddenNode(lane, top + lane.nodes.length * rowGap, nodeWidth, nodeHeight) : ""}
            </g>
          `).join("")}
        </svg>
      </div>
      <p class="muted">${state.language === "zh"
        ? "这是一版完整拓扑预览：优先展示有关系的资产，长尾资产按类型折叠。"
        : "Preview mode: connected assets are prioritized, long-tail resources are folded by type."}</p>
    `;
  }

  function miniStat(label, value) {
    return `
      <div class="mini-card">
        <div class="mini-value">${number(value)}</div>
        <div class="metric-label">${escapeHTML(label)}</div>
      </div>
    `;
  }

  function topologyLaneDefinitions() {
    return [
      { key: "entry", en: "Entry", zh: "入口", limit: 8 },
      { key: "compute", en: "Compute", zh: "计算", limit: 10 },
      { key: "network", en: "Network & Policy", zh: "网络与策略", limit: 10 },
      { key: "data", en: "Data", zh: "数据", limit: 8 },
      { key: "identity", en: "Identity", zh: "身份", limit: 8 },
      { key: "other", en: "Other", zh: "其他", limit: 6 },
    ];
  }

  function topologyLaneLabel(lane) {
    return state.language === "zh" ? lane.zh : lane.en;
  }

  function topologyLink(edge) {
    const sourceX = edge.source.x + edge.source.width;
    const sourceY = edge.source.y + edge.source.height / 2;
    const targetX = edge.target.x;
    const targetY = edge.target.y + edge.target.height / 2;
    const mid = Math.max(28, Math.abs(targetX - sourceX) * 0.42);
    const tone = edge.type === "uses_security_group" ? "policy" : (edge.type === "controls_data" ? "control" : "");
    return `<path class="topology-link ${escapeHTML(tone)}" d="M ${sourceX} ${sourceY} C ${sourceX + mid} ${sourceY}, ${targetX - mid} ${targetY}, ${targetX} ${targetY}"></path>`;
  }

  function topologyNode(node) {
    return `
      <g class="topology-node ${escapeHTML(node.lane)}"${assetDataAttributes(node.asset)}>
        <title>${escapeHTML(node.title)}</title>
        <rect x="${node.x}" y="${node.y}" width="${node.width}" height="${node.height}" rx="12"></rect>
        <text class="topology-node-title" x="${node.x + 10}" y="${node.y + 16}">${escapeHTML(shortTopologyLabel(node.label))}</text>
        <text class="topology-node-type" x="${node.x + 10}" y="${node.y + 30}">${escapeHTML(node.type)}</text>
      </g>
    `;
  }

  function topologyHiddenNode(lane, y, width, height) {
    const text = state.language === "zh" ? `另有 ${number(lane.hidden)} 个` : `+${number(lane.hidden)} more`;
    return `
      <g class="topology-node hidden">
        <rect x="${lane.x}" y="${y}" width="${width}" height="${height}" rx="12"></rect>
        <text class="topology-node-title" x="${lane.x + 10}" y="${y + 23}">${escapeHTML(text)}</text>
      </g>
    `;
  }

  function topologyNodeFromAsset(asset, lane) {
    return {
      id: topologyAssetKey(asset),
      lane,
      label: asset.name || nativeID(asset.resource_id) || asset.id,
      type: asset.resource_type || "unknown",
      asset,
      title: `${asset.resource_type || "unknown"} · ${asset.name || nativeID(asset.resource_id) || asset.resource_id || asset.id}`,
    };
  }

  function addTopologyEdge(edges, connected, source, target, type) {
    const sourceKey = topologyResourceKey(source);
    const targetKey = topologyResourceKey(target);
    if (!sourceKey || !targetKey || sourceKey === targetKey) {
      return;
    }
    const id = `${sourceKey}->${targetKey}:${type || "related"}`;
    if (edges.some((edge) => edge.id === id)) {
      return;
    }
    edges.push({ id, source: sourceKey, target: targetKey, type: type || "related" });
    connected.add(sourceKey);
    connected.add(targetKey);
  }

  function topologyAssetSort(left, right, connected, priority) {
    const leftPriority = priority.has(topologyAssetKey(left)) ? 1 : 0;
    const rightPriority = priority.has(topologyAssetKey(right)) ? 1 : 0;
    if (leftPriority !== rightPriority) {
      return rightPriority - leftPriority;
    }
    const leftConnected = connected.has(topologyAssetKey(left)) ? 1 : 0;
    const rightConnected = connected.has(topologyAssetKey(right)) ? 1 : 0;
    if (leftConnected !== rightConnected) {
      return rightConnected - leftConnected;
    }
    return (left.name || left.resource_id || "").localeCompare(right.name || right.resource_id || "");
  }

  function topologyLaneKey(asset) {
    if (isLoadBalancer(asset.resource_type)) {
      return "entry";
    }
    const group = resourceTypeGroupKey(asset.resource_type);
    if (group === "network") {
      return "network";
    }
    return group;
  }

  function topologyAssetKey(asset) {
    return topologyResourceKey(asset.resource_id || asset.id);
  }

  function topologyResourceKey(value) {
    return nativeID(value || "");
  }

  function shortTopologyLabel(value) {
    const text = stringValue(value);
    return text.length > 18 ? `${text.slice(0, 17)}...` : text;
  }

  function extractListeners(attributes) {
    const listeners = [];
    normalizeList(valueFrom(attributes, ["Listeners", "listeners"], [])).forEach((entry) => {
      const listener = firstObject([entry.Listener, entry.ListenerAttribute, entry.listener, entry]);
      if (!listener || !Object.keys(listener).length) {
        return;
      }
      const startPort = stringValue(valueFrom(listener, ["StartPort"], ""));
      const endPort = stringValue(valueFrom(listener, ["EndPort"], ""));
      listeners.push({
        port: stringValue(valueFrom(listener, ["ListenerPort", "Port"], "")) || (startPort && endPort ? `${startPort}-${endPort}` : startPort),
        protocol: stringValue(valueFrom(listener, ["ListenerProtocol", "Protocol"], "")),
        status: stringValue(valueFrom(listener, ["Status", "ListenerStatus"], "")),
        aclStatus: stringValue(valueFrom(listener, ["AclStatus"], "")),
        aclType: stringValue(valueFrom(listener, ["AclType"], "")),
        aclOff: lower(valueFrom(listener, ["AclStatus"], "")) === "off",
      });
    });
    return listeners;
  }

  function extractBackendRefs(attributes) {
    const refs = [];
    walkObjects(attributes, (node) => {
      const serverID = stringValue(valueFrom(node, ["ServerId", "serverId"], ""));
      const serverType = stringValue(valueFrom(node, ["ServerType", "Type", "serverType", "type"], ""));
      if (!serverID || (!looksLikeECSID(serverID) && lower(serverType) !== "ecs")) {
        return;
      }
      refs.push({
        id: serverID,
        type: serverType || "ecs",
        ip: stringValue(valueFrom(node, ["ServerIp", "serverIp"], "")),
        port: stringValue(valueFrom(node, ["Port", "port"], "")),
        weight: stringValue(valueFrom(node, ["Weight", "weight"], "")),
        status: stringValue(valueFrom(node, ["Status", "status"], "")),
      });
    });
    return dedupeByKey(refs.map((item) => ({ ...item, key: `${item.id}:${item.port}` })));
  }

  function securityGroupSummary(asset, fallbackID) {
    const properties = parseMaybeJSON(asset && asset.properties) || {};
    const attributes = properties.attributes || properties.Attributes || properties;
    const group = firstObject([attributes.SecurityGroup, attributes.securityGroup, {}]);
    const policies = normalizeList(valueFrom(attributes, ["Permissions", "permissions"], []))
      .map((policy) => securityGroupPolicy(policy))
      .filter(Boolean);
    const resourceID = (asset && asset.resource_id) || fallbackID;
    return {
      key: resourceID || fallbackID,
      asset,
      name: (asset && asset.name) || stringValue(valueFrom(group, ["SecurityGroupName", "securityGroupName"], "")) || nativeID(resourceID || fallbackID),
      resourceID,
      nativeID: nativeID(resourceID || fallbackID),
      policies,
      openPolicies: policies.filter((policy) => policy.open),
    };
  }

  function securityGroupPolicy(policy) {
    const direction = lower(valueFrom(policy, ["Direction", "direction"], ""));
    const action = lower(valueFrom(policy, ["Policy", "policy"], ""));
    const source = firstNonEmpty([
      valueFrom(policy, ["SourceCidrIp", "sourceCidrIp"], ""),
      valueFrom(policy, ["Ipv6SourceCidrIp", "ipv6SourceCidrIp"], ""),
      valueFrom(policy, ["SourceGroupId", "sourceGroupId"], ""),
    ]);
    const protocol = stringValue(valueFrom(policy, ["IpProtocol", "ipProtocol"], "ALL")).toUpperCase();
    const port = stringValue(valueFrom(policy, ["PortRange", "portRange"], "*"));
    return {
      id: stringValue(valueFrom(policy, ["SecurityGroupRuleId", "securityGroupRuleId"], "")),
      direction,
      action,
      source,
      protocol,
      port,
      priority: stringValue(valueFrom(policy, ["Priority", "priority"], "")),
      description: stringValue(valueFrom(policy, ["Description", "description"], "")),
      open: direction === "ingress" && action !== "drop" && isAnySource(source),
    };
  }

  function resolveAsset(assetIndex, resourceID, preferredType, preferredRegion) {
    if (!resourceID) {
      return null;
    }
    const direct = assetIndex.byResourceID.get(resourceID);
    if (assetMatches(direct, preferredType, preferredRegion)) {
      return direct;
    }
    const candidates = assetIndex.byNativeID.get(lower(nativeID(resourceID) || resourceID)) || [];
    return candidates.find((asset) => assetMatches(asset, preferredType, preferredRegion)) ||
      candidates.find((asset) => assetMatches(asset, preferredType)) ||
      direct ||
      candidates[0] ||
      null;
  }

  function assetMatches(asset, preferredType, preferredRegion) {
    if (!asset) {
      return false;
    }
    if (preferredType && canonicalType(asset.resource_type) !== canonicalType(preferredType)) {
      return false;
    }
    if (preferredRegion && asset.region && preferredRegion !== asset.region) {
      return false;
    }
    return true;
  }

  function assetNativeIDs(asset) {
    const ids = [nativeID(asset.resource_id), nativeID(asset.id)];
    const properties = parseMaybeJSON(asset.properties) || {};
    const attributes = properties.attributes || properties.Attributes || properties;
    const resource = firstObject([attributes.LoadBalancer, attributes.LoadBalancerAttribute, attributes.SecurityGroup, {}]);
    ["LoadBalancerId", "SecurityGroupId", "InstanceId"].forEach((key) => {
      ids.push(stringValue(valueFrom(resource, [key], "")));
    });
    return unique(ids);
  }

  function assetAttributes(asset) {
    const properties = parseMaybeJSON(asset && asset.properties) || {};
    return properties.attributes || properties.Attributes || properties;
  }

  function dataAssetType(type) {
    const normalized = canonicalType(type);
    if (normalized === "oss" || normalized.includes("bucket")) {
      return "OSS";
    }
    if (normalized === "sls" || normalized === "logservice" || normalized.includes("logstore") || normalized.includes("logproject")) {
      return "SLS";
    }
    if (normalized === "redis" || normalized.includes("kvstore")) {
      return "Redis";
    }
    if (normalized === "mongodb" || normalized.includes("dds")) {
      return "MongoDB";
    }
    if (normalized === "polardb") {
      return "PolarDB";
    }
    if (normalized === "clickhouse") {
      return "ClickHouse";
    }
    if (normalized === "lindorm" || normalized === "hitsdb") {
      return "Lindorm";
    }
    if (normalized === "hbase") {
      return "HBase";
    }
    if (normalized === "elasticsearch") {
      return "Elasticsearch";
    }
    if (normalized === "kafka" || normalized === "alikafka") {
      return "Kafka";
    }
    if (normalized === "rocketmq" || normalized === "mq" || normalized === "ons") {
      return "RocketMQ";
    }
    if (normalized === "rds" || normalized.includes("dbinstance") || normalized.includes("database") || normalized.includes("analyticdb")) {
      return "RDS";
    }
    return "";
  }

  function publicBucketPolicySummary(value, policyStatusPublic) {
    const statements = policyStatements(value);
    const publicStatements = statements.filter((statement) => {
      const effect = lower(valueFrom(statement, ["Effect", "effect"], "allow"));
      return effect === "allow" && statementAllowsPublicPrincipal(statement) && !statementHasRestrictivePublicCondition(statement);
    });
    const actions = publicStatements.flatMap((statement) => policyActions(statement));
    return {
      public: policyStatusPublic === undefined ? publicStatements.length > 0 : truthy(policyStatusPublic),
      read: actions.some((action) => ossReadAction(action)),
      write: actions.some((action) => ossWriteAction(action)),
    };
  }

  function statementAllowsPublicPrincipal(statement) {
    const principals = flattenValues(valueFrom(statement, ["Principal", "principal"], ""));
    return principals.some((value) => String(value).trim() === "*");
  }

  function statementHasRestrictivePublicCondition(statement) {
    const condition = parseMaybeJSON(valueFrom(statement, ["Condition", "condition"], null));
    if (!condition || typeof condition !== "object") {
      return false;
    }
    return conditionRestrictsSourceVPC(condition) || conditionRestrictsSourceIP(condition) || conditionRestrictsAccessID(condition);
  }

  function conditionRestrictsSourceVPC(condition) {
    return conditionValuesForKey(condition, "acs:SourceVpc").some((value) => {
      const text = lower(value);
      return text.startsWith("vpc-") && !text.includes("*");
    });
  }

  function conditionRestrictsAccessID(condition) {
    return conditionValuesForKey(condition, "acs:AccessId").some((value) => {
      const text = String(value || "").trim();
      return text !== "" && text !== "*" && !text.includes("*");
    });
  }

  function conditionRestrictsSourceIP(condition) {
    return conditionValuesForKey(condition, "acs:SourceIp").some((value) => {
      const text = String(value || "").trim();
      const prefix = cidrPrefixLength(text);
      if (prefix === null) {
        return Boolean(text && !text.includes("*"));
      }
      return text.includes(":") ? prefix >= 32 : prefix >= 8;
    });
  }

  function conditionValuesForKey(condition, conditionKey) {
    const values = [];
    walkObjects(condition, (node) => {
      Object.entries(node).forEach(([key, value]) => {
        if (lower(key) === lower(conditionKey)) {
          values.push(...flattenValues(value));
        }
      });
    });
    return values;
  }

  function cidrPrefixLength(value) {
    const parts = String(value || "").split("/");
    if (parts.length !== 2) {
      return null;
    }
    const prefix = Number(parts[1]);
    return Number.isInteger(prefix) ? prefix : null;
  }

  function ossDataAction(action) {
    const normalized = lower(action);
    return normalized === "*" || normalized === "oss:*" || normalized.startsWith("oss:get") || normalized.startsWith("oss:list") || ossWriteAction(normalized);
  }

  function ossReadAction(action) {
    const normalized = lower(action);
    return normalized === "*" || normalized === "oss:*" || normalized.startsWith("oss:get") || normalized.startsWith("oss:list");
  }

  function ossWriteAction(action) {
    const normalized = lower(action);
    return normalized === "*" || normalized === "oss:*" ||
      normalized.startsWith("oss:put") ||
      normalized.startsWith("oss:delete") ||
      normalized.startsWith("oss:create") ||
      normalized.startsWith("oss:set");
  }

  function hasPublicDataEndpoint(attributes) {
    let found = false;
    walkObjects(attributes, (node) => {
      if (found) {
        return;
      }
      const networkType = lower(firstNonEmpty([
        valueFrom(node, ["DBInstanceNetType", "dbInstanceNetType"], ""),
        valueFrom(node, ["IPType", "ipType"], ""),
        valueFrom(node, ["NetType", "netType"], ""),
        valueFrom(node, ["NetworkType", "networkType"], ""),
        valueFrom(node, ["ConnectionStringType", "connectionStringType"], ""),
      ]));
      if (networkType && (isPublicAddress(networkType) || /internet|public|extranet|wan/.test(networkType))) {
        found = true;
        return;
      }
      const ipAddress = stringValue(firstNonEmpty([
        valueFrom(node, ["IPAddress", "ipAddress"], ""),
        valueFrom(node, ["IP", "ip"], ""),
        valueFrom(node, ["Address", "address"], ""),
      ]));
      if (ipAddress && isPublicIPv4(ipAddress) && /public|internet|extranet/.test(networkType)) {
        found = true;
      }
    });
    return found;
  }

  function collectAccessListEntries(attributes) {
    const entries = [];
    walkObjects(attributes, (node) => {
      [
        "SecurityIPList",
        "SecurityIpList",
        "securityIPList",
        "securityIpList",
        "SecurityIps",
        "securityIps",
        "Whitelist",
        "whiteList",
      ].forEach((key) => {
        const value = node[key];
        if (value !== undefined && value !== null) {
          entries.push(...splitListValues(value));
        }
      });
    });
    return unique(entries.map((entry) => stringValue(entry).trim()).filter(Boolean));
  }

  function isRAMUser(type) {
    const normalized = canonicalType(type);
    return normalized === "ramuser" || normalized.includes("ramuser");
  }

  function accessKeySummaries(attributes) {
    const rawKeys = [
      ...normalizeList(valueFrom(attributes, ["AccessKeys", "accessKeys"], [])),
      ...normalizeList(valueFrom(attributes, ["AccessKey", "accessKey"], [])),
    ];
    return rawKeys.map((item) => firstObject([item.AccessKey, item.accessKey, item]))
      .filter((item) => item && Object.keys(item).length)
      .map((item) => {
        const status = lower(valueFrom(item, ["Status", "status", "State", "state"], ""));
        const id = maskedAccessKeyID(stringValue(valueFrom(item, ["AccessKeyId", "AccessKeyID", "accessKeyId", "access_key_id"], "")));
        return {
          id,
          active: ["active", "enabled", "enable"].includes(status),
          inactive: ["inactive", "disabled", "disable", "deleted"].includes(status),
        };
      });
  }

  function policySummaries(attributes) {
    return normalizeList(valueFrom(attributes, ["Policies", "policies"], []))
      .map((item) => firstObject([item.Policy, item.policy, item]))
      .filter((policy) => policy && Object.keys(policy).length)
      .map((policy) => {
        const statements = policyDocumentStatements(policy);
        return {
          name: stringValue(valueFrom(policy, ["PolicyName", "policyName", "name"], "")),
          type: stringValue(valueFrom(policy, ["PolicyType", "policyType", "type"], "")),
          documentCollected: statements.length > 0,
          statements,
          sourceConditions: sourceConditionsFromStatements(statements),
          actions: statements.flatMap((statement) => policyActions(statement)),
          sourceGuard: statements.some((statement) => lower(valueFrom(statement, ["Effect", "effect"], "")) === "deny" && statementHasIdentitySourceRestriction(statement)),
        };
      });
  }

  function policyDocumentStatements(policy) {
    const version = firstObject([
      valueFrom(policy, ["DefaultPolicyVersion", "defaultPolicyVersion"], null),
      valueFrom(policy, ["PolicyVersion", "policyVersion"], null),
      policy,
    ]);
    const document = firstDefined([
      valueFrom(version, ["PolicyDocument", "policyDocument"], ""),
      valueFrom(policy, ["PolicyDocument", "policyDocument"], ""),
    ]);
    return policyStatements(document);
  }

  function policyDataServices(policies) {
    const services = new Map();
    policies.forEach((policy) => {
      if (!policy.statements.length) {
        addServicesFromPolicyName(services, policy.name, false);
      }
      policy.statements
        .filter((statement) => lower(valueFrom(statement, ["Effect", "effect"], "allow")) === "allow")
        .forEach((statement) => {
          const statementRestricted = statementHasIdentitySourceRestriction(statement);
          const resources = policyResources(statement);
          policyActions(statement).forEach((action) => addServiceFromAction(services, action, statementRestricted, resources));
        });
    });
    return Array.from(services.values())
      .sort((left, right) => serviceRank(right.level) - serviceRank(left.level) || left.name.localeCompare(right.name));
  }

  function addServicesFromPolicyName(services, name, sourceRestricted) {
    const normalized = lower(name);
    if (!normalized) {
      return;
    }
    if (normalized.includes("administratoraccess")) {
      knownDataServices().forEach((service) => addDataService(services, service, "full access", sourceRestricted, ["*"]));
      return;
    }
    serviceNameMatchers().forEach(([needle, service]) => {
      if (!normalized.includes(needle)) {
        return;
      }
      const level = normalized.includes("readonly") || normalized.includes("readonlyaccess") ? "read access" : "full access";
      addDataService(services, service, level, sourceRestricted, ["*"]);
    });
  }

  function addServiceFromAction(services, action, sourceRestricted, resources) {
    const normalized = lower(action);
    if (!normalized) {
      return;
    }
    if (normalized === "*" || normalized === "*:*") {
      knownDataServices().forEach((service) => addDataService(services, service, "full access", sourceRestricted, resources));
      return;
    }
    const service = actionServiceName(normalized);
    if (!service) {
      return;
    }
    addDataService(services, service, actionPermissionLevel(normalized), sourceRestricted, resources);
  }

  function addDataService(services, name, level, sourceRestricted, resources) {
    const existing = services.get(name);
    const pathKind = credentialPathKind(name, level);
    if (!existing || serviceRank(level) > serviceRank(existing.level)) {
      services.set(name, {
        name,
        level,
        pathKind,
        sourceRestricted: Boolean(sourceRestricted),
        resourcePatterns: unique(resources || ["*"]),
      });
      return;
    }
    existing.sourceRestricted = existing.sourceRestricted && Boolean(sourceRestricted);
    existing.resourcePatterns = unique([...(existing.resourcePatterns || []), ...(resources || ["*"])]);
    if (serviceRank(level) === serviceRank(existing.level) && credentialPathRank(pathKind) > credentialPathRank(existing.pathKind)) {
      existing.pathKind = pathKind;
    }
  }

  function actionServiceName(action) {
    const prefix = lower(String(action || "").split(":")[0]);
    if (prefix === "oss") {
      return "OSS";
    }
    if (prefix === "log" || prefix === "sls") {
      return "SLS";
    }
    if (prefix === "rds" || prefix === "dbs" || prefix === "hdm") {
      return "RDS";
    }
    if (prefix === "kvstore" || prefix === "redis") {
      return "Redis";
    }
    if (prefix === "dds" || prefix === "mongodb") {
      return "MongoDB";
    }
    if (prefix === "polardb") {
      return "PolarDB";
    }
    if (prefix === "clickhouse") {
      return "ClickHouse";
    }
    if (prefix === "hitsdb" || prefix === "lindorm") {
      return "Lindorm";
    }
    if (prefix === "hbase") {
      return "HBase";
    }
    if (prefix === "elasticsearch" || prefix === "es") {
      return "Elasticsearch";
    }
    if (prefix === "alikafka" || prefix === "kafka") {
      return "Kafka";
    }
    if (prefix === "mq" || prefix === "ons" || prefix === "rocketmq") {
      return "RocketMQ";
    }
    return "";
  }

  function actionPermissionLevel(action) {
    const normalized = lower(action);
    if (normalized.includes("*")) {
      return "full access";
    }
    const operation = normalized.split(":")[1] || normalized;
    if (/^(put|post|delete|create|modify|update|set|attach|grant|reset|add|remove|allocate|release)/.test(operation)) {
      return "manage access";
    }
    return "read access";
  }

  function dataServiceForType(type) {
    if (knownDataServices().includes(type)) {
      return type;
    }
    return "";
  }

  function serviceMatchesDataServices(service, dataServices) {
    if (!knownDataServices().includes(service)) {
      return false;
    }
    return dataServices.size ? dataServices.has(service) : true;
  }

  function serviceMatchesDataTarget(service, target) {
    const dataService = dataServiceForType(target.type);
    return Boolean(service && dataService && service.name === dataService && targetResourceMatchesService(service, target));
  }

  function targetResourceMatchesService(service, target) {
    const patterns = service.resourcePatterns && service.resourcePatterns.length ? service.resourcePatterns : ["*"];
    if (patterns.includes("*")) {
      return true;
    }
    const targetIDs = [
      target.resourceID,
      target.asset && target.asset.resource_id,
      target.asset && target.asset.id,
      target.name,
      nativeID(target.resourceID),
    ].filter(Boolean).map((value) => lower(value));
    return patterns.some((pattern) => {
      const normalized = lower(pattern);
      if (!normalized || normalized === "*") {
        return true;
      }
      if (targetIDs.some((id) => normalized.includes(id) || id.includes(normalized))) {
        return true;
      }
      if (normalized.includes("*")) {
        const regex = new RegExp("^" + normalized.split("*").map(escapeRegExp).join(".*") + "$");
        return targetIDs.some((id) => regex.test(id));
      }
      return targetIDs.some((id) => normalized.includes(id) || id.includes(normalized));
    });
  }

  function credentialPathKind(service, level) {
    if (service === "OSS" || service === "SLS") {
      return "data-plane access";
    }
    return level === "read access" ? "management-plane visibility" : "management-plane change";
  }

  function credentialPathMode(service, target) {
    if (!service) {
      return "management-plane change";
    }
    if (target && (target.type === "OSS" || target.type === "SLS") && service.name === target.type) {
      return "data-plane access";
    }
    return service.level === "read access" ? "management-plane visibility" : "management-plane change";
  }

  function credentialPathRank(kind) {
    return {
      "management-plane visibility": 1,
      "management-plane change": 2,
      "data-plane access": 3,
    }[kind] || 0;
  }

  function policyResources(statement) {
    return flattenValues(valueFrom(statement, ["Resource", "resource"], "*")).map((item) => stringValue(item)).filter(Boolean);
  }

  function statementHasIdentitySourceRestriction(statement) {
    const condition = parseMaybeJSON(valueFrom(statement, ["Condition", "condition"], null));
    if (!condition || typeof condition !== "object") {
      return false;
    }
    return conditionRestrictsSourceVPC(condition) || conditionRestrictsSourceIP(condition) || conditionRestrictsAccessID(condition);
  }

  function knownDataServices() {
    return ["OSS", "SLS", "RDS", "Redis", "MongoDB", "PolarDB", "ClickHouse", "Lindorm", "HBase", "Elasticsearch", "Kafka", "RocketMQ"];
  }

  function serviceNameMatchers() {
    return [
      ["oss", "OSS"],
      ["sls", "SLS"],
      ["aliyunlog", "SLS"],
      ["logfullaccess", "SLS"],
      ["logreadonlyaccess", "SLS"],
      ["rds", "RDS"],
      ["kvstore", "Redis"],
      ["redis", "Redis"],
      ["mongodb", "MongoDB"],
      ["dds", "MongoDB"],
      ["polardb", "PolarDB"],
      ["clickhouse", "ClickHouse"],
      ["lindorm", "Lindorm"],
      ["hbase", "HBase"],
      ["elasticsearch", "Elasticsearch"],
      ["kafka", "Kafka"],
      ["rocketmq", "RocketMQ"],
    ];
  }

  function policyStatements(value) {
    const document = parseMaybeJSON(value);
    if (!document || typeof document !== "object") {
      return [];
    }
    if (Array.isArray(document)) {
      return document.filter((item) => item && typeof item === "object");
    }
    const statement = parseMaybeJSON(valueFrom(document, ["Statement", "statement", "Statements", "statements"], []));
    if (Array.isArray(statement)) {
      return statement.filter((item) => item && typeof item === "object");
    }
    if (statement && typeof statement === "object") {
      return [statement];
    }
    return [];
  }

  function policyActions(statement) {
    return flattenValues(valueFrom(statement, ["Action", "action"], [])).map((action) => stringValue(action)).filter(Boolean);
  }

  function flattenValues(value) {
    const parsed = parseMaybeJSON(value);
    if (Array.isArray(parsed)) {
      return parsed.flatMap((item) => flattenValues(item));
    }
    if (parsed && typeof parsed === "object") {
      return Object.values(parsed).flatMap((item) => flattenValues(item));
    }
    return parsed === undefined || parsed === null || parsed === "" ? [] : [parsed];
  }

  function splitListValues(value) {
    return flattenValues(value).flatMap((item) => String(item).split(/[,\s;]+/)).filter(Boolean);
  }

  function redactSensitiveJSON(value, seen = new WeakSet()) {
    if (Array.isArray(value)) {
      return value.map((item) => redactSensitiveJSON(item, seen));
    }
    if (value && typeof value === "object") {
      if (seen.has(value)) {
        return "[circular]";
      }
      seen.add(value);
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [
        key,
        sensitiveJSONKey(key) ? "[redacted]" : redactSensitiveJSON(item, seen),
      ]));
    }
    if (typeof value === "string") {
      return redactSensitiveString(value);
    }
    return value;
  }

  function sensitiveJSONKey(key) {
    const normalized = lower(String(key || "").replace(/[-\s]/g, "_"));
    return ["access_key", "accesskey", "secret", "token", "password", "passwd", "credential", "ak", "sk"]
      .some((token) => normalized === token || normalized.includes(token));
  }

  function redactSensitiveString(value) {
    const text = String(value || "");
    if (/^LTAI[A-Za-z0-9]{12,}$/.test(text.trim())) {
      return "[redacted]";
    }
    return text;
  }

  function shellToken(value) {
    const text = String(value || "");
    if (!text) {
      return "''";
    }
    if (/^[A-Za-z0-9._/:=-]+$/.test(text)) {
      return text;
    }
    return `'${text.replace(/'/g, "'\"'\"'")}'`;
  }

  function riskRank(severity) {
    return {
      info: 1,
      low: 2,
      medium: 3,
      high: 4,
      critical: 5,
    }[lower(severity)] || 0;
  }

  function serviceRank(level) {
    return {
      "read access": 1,
      "manage access": 2,
      "full access": 3,
    }[level] || 0;
  }

  function isLoadBalancer(type) {
    return ["slb", "alb", "nlb"].includes(canonicalType(type));
  }

  function isPublicAddress(addressType) {
    return ["internet", "public", "publicnetwork"].includes(canonicalType(addressType));
  }

  function hasPublicAddress(loadBalancer) {
    const address = stringValue(valueFrom(loadBalancer, ["Address", "DNSName"], ""));
    const match = address.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return Boolean(match && isPublicIPv4(match[0]));
  }

  function isPublicIPv4(value) {
    const parts = String(value || "").split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return false;
    }
    const [first, second] = parts;
    if (first === 10 || first === 127 || first === 0) {
      return false;
    }
    if (first === 172 && second >= 16 && second <= 31) {
      return false;
    }
    if (first === 192 && second === 168) {
      return false;
    }
    if (first === 169 && second === 254) {
      return false;
    }
    return first < 224;
  }

  function firstLoadBalancerAddress(loadBalancer) {
    let address = "";
    walkObjects(loadBalancer, (node) => {
      if (!address) {
        address = stringValue(valueFrom(node, ["Address", "PrivateIPv4Address", "IntranetAddress"], ""));
      }
    });
    return address;
  }

  function looksLikeECSID(value) {
    return /^i-[a-z0-9]+/i.test(nativeID(value) || value);
  }

  function looksLikeSecurityGroupID(value) {
    return canonicalType(value).includes("securitygroup") || /^sg-[a-z0-9]+/i.test(nativeID(value) || value);
  }

  function isAnySource(source) {
    const value = String(source || "").trim();
    return value === "0.0.0.0/0" || value === "::/0" || value === "0.0.0.0" || value === "all";
  }

  function nativeID(value) {
    const text = stringValue(value);
    if (!text) {
      return "";
    }
    const parts = text.split(/[?#]/)[0].split("/").filter(Boolean);
    return parts[parts.length - 1] || text;
  }

  function canonicalType(value) {
    return lower(value).replace(/[^a-z0-9]/g, "");
  }

  function normalizeList(value) {
    const parsed = parseMaybeJSON(value);
    if (!parsed) {
      return [];
    }
    if (Array.isArray(parsed)) {
      return parsed;
    }
    if (typeof parsed === "object") {
      for (const item of Object.values(parsed)) {
        if (Array.isArray(item)) {
          return item;
        }
      }
      return [parsed];
    }
    return [];
  }

  function firstObject(values) {
    return values.find((value) => value && typeof value === "object" && !Array.isArray(value)) || {};
  }

  function firstNonEmpty(values) {
    for (const value of values) {
      const text = stringValue(value).trim();
      if (text) {
        return text;
      }
    }
    return "";
  }

  function firstDefined(values) {
    return values.find((value) => value !== undefined && value !== null && value !== "") || "";
  }

  function walkObjects(value, visitor, seen = new Set()) {
    const parsed = parseMaybeJSON(value);
    if (!parsed || typeof parsed !== "object" || seen.has(parsed)) {
      return;
    }
    seen.add(parsed);
    if (!Array.isArray(parsed)) {
      visitor(parsed);
    }
    Object.values(parsed).forEach((item) => {
      if (item && typeof item === "object") {
        walkObjects(item, visitor, seen);
      }
    });
  }

  function dedupeByKey(items) {
    const seen = new Set();
    return items.filter((item) => {
      const key = item && item.key;
      if (!key || seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  function apiTiles() {
    return endpoints.map((endpoint) => {
      const health = state.apiHealth.get(endpoint) || {};
      return `
        <div class="api-tile">
          <code>${escapeHTML(endpoint)}</code>
          ${statusChip(health.ok ? "ok" : health.status || "not called")}
          <p class="muted">${escapeHTML(health.message || "Will be called by the related page or drawer.")}</p>
        </div>
      `;
    }).join("");
  }

  function detailList(values) {
    return `<div class="detail-list">${Object.entries(values || {})
      .filter(([, value]) => value !== undefined && value !== null && value !== "")
      .map(([key, value]) => detailRow(key, value))
      .join("") || `<p class="muted">No detail fields.</p>`}</div>`;
  }

  function detailRow(label, value) {
    return `
      <div class="detail-row">
        <span class="meta-label">${escapeHTML(fieldLabel(label))}</span>
        <span>${escapeHTML(localizedDetailValue(label, value))}</span>
      </div>
    `;
  }

  function localizedDetailValue(label, value) {
    const normalized = String(label || "").toLowerCase();
    if (normalized === "severity") {
      return translateValue("severity", value);
    }
    if (normalized === "status") {
      return translateValue("status", value);
    }
    return displayValue(value);
  }

  function fieldLabel(label) {
    if (state.language !== "zh") {
      return label;
    }
    const normalized = String(label || "").toLowerCase();
    const labels = {
      id: "ID",
      title: "标题",
      severity: "严重度",
      status: "状态",
      rule_id: "规则 ID",
      asset_id: "资产 ID",
      account_id: "账号 ID",
      resource_type: "资源类型",
      resource_id: "资源 ID",
      region: "地域",
      provider: "云厂商",
      name: "名称",
      message: "风险说明",
      remediation: "修复建议",
      first_seen_at: "首次发现",
      last_seen_at: "最近发现",
      relationship_type: "连线类型",
      source_resource_type: "源资源类型",
      source_resource_id: "源资源 ID",
      target_resource_id: "目标资源 ID",
      updated_at: "更新时间",
      started_at: "开始时间",
      finished_at: "结束时间",
      assets: "资产数",
      findings: "风险数",
      database: "数据库",
      rules: "规则目录",
      writes: "写操作",
      limit: "返回数量",
      "latest scan": "最近扫描",
      account_id_filter: "账号",
      provider_filter: "云厂商",
      resource_type_filter: "资源",
    };
    return labels[normalized] || zhPhrases[label] || label;
  }

  async function refreshRuntime() {
    const runtime = await api.runtime();
    state.runtime = runtime;
    applyRuntimeHealth(runtime);
  }

  async function hydrateFilterFacets() {
    populateResourceTypeOptions(state.facets);
    try {
      const facets = await api.facets({ resource_type: "" });
      state.facets = facets;
      populateResourceTypeOptions(facets);
    } catch (error) {
      // Keep the built-in catalog if facets are unavailable.
    }
  }

  function applyRuntimeHealth(runtime) {
    const ok = runtime.status === "ok" || runtime.status === "healthy" || runtime.status === "ready";
    const bad = runtime.status === "error" || runtime.status === "failed" || runtime.status === "unavailable";
    el.healthDot.className = "health-dot" + (ok ? " ok" : bad ? " bad" : "");
    el.healthLabel.textContent = ok ? t("status.online") : bad ? t("status.issue") : t("status.unknown");
  }

  async function fetchJSON(path, params, options) {
    const opts = options || {};
    const url = new URL(path, window.location.origin);
    Object.entries(params || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        url.searchParams.set(key, value);
      }
    });

    try {
      const response = await fetch(url.pathname + url.search, {
        headers: { Accept: "application/json" },
      });
      const text = await response.text();
      const body = parseJSON(text);
      if (!response.ok) {
        throw new Error(errorMessage(body, response.statusText || "Request failed"));
      }
      markAPI(path, true, response.status, "ok");
      return body;
    } catch (error) {
      markAPI(path, false, "error", error.message || "request failed");
      if (opts.optional) {
        return null;
      }
      throw error;
    }
  }

  async function firstJSON(candidates, options) {
    let lastError = null;
    for (const candidate of candidates) {
      try {
        const body = await fetchJSON(candidate.path, candidate.params, { optional: false });
        return body;
      } catch (error) {
        lastError = error;
      }
    }
    if (options && options.optional) {
      return null;
    }
    throw lastError || new Error("No API endpoint responded");
  }

  function markAPI(path, ok, status, message) {
    state.apiHealth.set(path, { ok, status, message });
  }

  function normalizeCollection(raw, keys, mapper) {
    const body = firstRecord(raw, ["data", "result"]) || raw || {};
    const items = listFrom(body, keys).map(mapper);
    return {
      items,
      count: numberValue(valueFrom(body, ["count"], items.length)),
      total: numberValue(valueFrom(body, ["total"], items.length)),
      limit: numberValue(valueFrom(body, ["limit"], state.filters.limit || items.length)),
      offset: numberValue(valueFrom(body, ["offset"], 0)),
      raw: body,
    };
  }

  function baseParams() {
    return compact({
      account_id: state.filters.account_id,
      provider: state.filters.provider,
      resource_type: state.filters.resource_type,
      limit: state.filters.limit,
    });
  }

  function pickParams(keys) {
    const params = {};
    keys.forEach((key) => {
      params[key] = state.filters[key];
    });
    return compact(params);
  }

  function findingsParams(overrides) {
    const params = {
      ...baseParams(),
      severity: state.filters.severity,
      status: findingStatuses.has(state.filters.status) ? state.filters.status : "",
      ...overrides,
    };
    return compact(params);
  }

  function assetParams(overrides) {
    return compact({ ...baseParams(), ...overrides });
  }

  function relationshipParams(overrides) {
    return compact({
      ...baseParams(),
      relationship_type: "",
      ...overrides,
    });
  }

  function scanParams(overrides) {
    return compact({
      account_id: state.filters.account_id,
      provider: state.filters.provider,
      status: scanStatuses.has(state.filters.status) ? state.filters.status : "",
      limit: state.filters.limit,
      ...overrides,
    });
  }

  function pageState(route) {
    if (!state.pages[route]) {
      state.pages[route] = { offset: 0, q: "", sort: "" };
    }
    return state.pages[route];
  }

  function pageRequest(route, extra) {
    const page = pageState(route);
    return compact({
      q: page.q,
      sort: page.sort,
      offset: page.offset,
      limit: state.filters.limit,
      ...extra,
    });
  }

  function resetPageOffsets() {
    Object.values(state.pages).forEach((page) => {
      page.offset = 0;
    });
  }

  function pageLimit() {
    const parsed = Number(state.filters.limit);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 50;
  }

  function normalizeDashboard(raw) {
    const body = firstRecord(raw, ["dashboard", "summary", "data", "result"]) || raw || {};
    const latestScan = valueFrom(body, ["latest_scan_run", "latestScanRun", "latest_scan", "scan"]);
    const severityCounts = normalizeCounts(valueFrom(body, ["severity_counts", "severityCounts", "severities", "by_severity"]));
    return {
      raw: body,
      accountID: valueFrom(body, ["account_id", "accountId"]),
      assetCount: numberValue(valueFrom(body, ["asset_count", "assetCount", "total_assets", "assets"], 0)),
      findingCount: numberValue(valueFrom(body, ["finding_count", "findingCount", "total_findings", "findings"], 0)),
      openFindingCount: numberValue(valueFrom(body, ["open_finding_count", "openFindingCount", "open_findings"], 0)),
      relationshipCount: numberValue(valueFrom(body, ["relationship_count", "relationshipCount", "relationships"], 0)),
      ruleCount: numberValue(valueFrom(body, ["rule_count", "ruleCount", "rules"], 0)),
      severityCounts,
      latestScanRun: latestScan ? normalizeScanRun(latestScan) : null,
      scanDelta: valueFrom(body, ["scan_delta", "scanDelta", "delta"], {}),
    };
  }

  function normalizeFacets(raw) {
    const body = firstRecord(raw, ["facets", "data", "result"]) || raw || {};
    return {
      accounts: facetValues(valueFrom(body, ["accounts", "account_ids", "accountIds"])),
      providers: facetValues(valueFrom(body, ["providers", "provider"])),
      resourceTypes: facetValues(valueFrom(body, ["resource_types", "resourceTypes", "asset_types", "assetTypes"])),
      severities: facetValues(valueFrom(body, ["severities", "severity"])),
      statuses: facetValues(valueFrom(body, ["statuses", "status"])),
      raw: body,
    };
  }

  function deriveFacets(collections) {
    return {
      accounts: facetFromValues([
        ...collections.findings.map((item) => item.account_id),
        ...collections.assets.map((item) => item.account_id),
        ...collections.scans.map((item) => item.account_id),
      ]),
      providers: facetFromValues([
        ...collections.assets.map((item) => item.provider),
        ...collections.scans.map((item) => item.provider),
      ]),
      resourceTypes: facetFromValues([
        ...collections.findings.map((item) => item.resource_type),
        ...collections.assets.map((item) => item.resource_type),
        ...collections.relationships.map((item) => item.source_resource_type),
      ]),
      severities: facetFromValues(collections.findings.map((item) => item.severity)),
      statuses: facetFromValues([
        ...collections.findings.map((item) => item.status),
        ...collections.scans.map((item) => item.status),
      ]),
      raw: collections,
    };
  }

  function normalizeFinding(item) {
    const raw = item || {};
    const asset = raw.asset || raw.resource || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id", "finding_id", "findingId"])) || stableID(raw),
      scan_run_id: stringValue(valueFrom(raw, ["scan_run_id", "scanRunId"])),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"], asset.account_id)),
      asset_id: stringValue(valueFrom(raw, ["asset_id", "assetId"], asset.id)),
      resource_id: stringValue(valueFrom(raw, ["resource_id", "resourceId"], asset.resource_id || asset.id)),
      resource_type: stringValue(valueFrom(raw, ["resource_type", "resourceType", "asset_type", "assetType"], asset.resource_type || asset.type)),
      rule_id: stringValue(valueFrom(raw, ["rule_id", "ruleId", "policy_id", "policyId", "rule"], "")),
      title: stringValue(valueFrom(raw, ["title", "name", "rule_name", "ruleName", "message"], "Untitled finding")),
      severity: lower(valueFrom(raw, ["severity", "level", "risk"], "unknown")),
      status: lower(valueFrom(raw, ["status", "state"], "open")),
      message: stringValue(valueFrom(raw, ["message", "description", "detail"], "")),
      evidence: valueFrom(raw, ["evidence", "proof"], null),
      remediation: stringValue(valueFrom(raw, ["remediation", "fix", "recommendation"], "")),
      first_seen_at: valueFrom(raw, ["first_seen_at", "firstSeenAt", "created_at", "createdAt"]),
      last_seen_at: valueFrom(raw, ["last_seen_at", "lastSeenAt", "updated_at", "updatedAt"]),
      updated_at: valueFrom(raw, ["updated_at", "updatedAt"]),
    };
  }

  function normalizeAsset(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id", "asset_id", "assetId"])) || stableID(raw),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"])),
      provider: stringValue(valueFrom(raw, ["provider", "cloud", "vendor"])),
      resource_type: stringValue(valueFrom(raw, ["resource_type", "resourceType", "asset_type", "assetType", "type"])),
      resource_id: stringValue(valueFrom(raw, ["resource_id", "resourceId", "external_id", "externalId"], raw.id)),
      region: stringValue(valueFrom(raw, ["region", "zone"], "")),
      name: stringValue(valueFrom(raw, ["name", "display_name", "displayName"], "")),
      properties: valueFrom(raw, ["properties", "attributes", "metadata"], null),
      productSummary: valueFrom(raw, ["product_summary", "productSummary"], null),
      first_seen_at: valueFrom(raw, ["first_seen_at", "firstSeenAt", "created_at", "createdAt"]),
      last_seen_at: valueFrom(raw, ["last_seen_at", "lastSeenAt", "updated_at", "updatedAt"]),
      updated_at: valueFrom(raw, ["updated_at", "updatedAt"]),
    };
  }

  function normalizeRelationship(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id", "relationship_id", "relationshipId"])) || stableID(raw),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"])),
      provider: stringValue(valueFrom(raw, ["provider", "cloud", "vendor"])),
      source_asset_id: stringValue(valueFrom(raw, ["source_asset_id", "sourceAssetId", "source_id", "sourceId"])),
      source_resource_type: stringValue(valueFrom(raw, ["source_resource_type", "sourceResourceType", "resource_type", "resourceType"])),
      source_resource_id: stringValue(valueFrom(raw, ["source_resource_id", "sourceResourceId", "source"], "")),
      relationship_type: stringValue(valueFrom(raw, ["relationship_type", "relationshipType", "type", "label"], "related_to")),
      target_resource_id: stringValue(valueFrom(raw, ["target_resource_id", "targetResourceId", "target"], "")),
      first_seen_at: valueFrom(raw, ["first_seen_at", "firstSeenAt", "created_at", "createdAt"]),
      last_seen_at: valueFrom(raw, ["last_seen_at", "lastSeenAt", "updated_at", "updatedAt"]),
      updated_at: valueFrom(raw, ["updated_at", "updatedAt"]),
    };
  }

  function normalizeRiskPaths(raw) {
    if (!raw) {
      return { available: false, summary: {}, paths: [], groups: [], trafficPaths: [], total: 0, groupsTotal: 0, trafficTotal: 0, trafficCount: 0, count: 0 };
    }
    const body = firstRecord(raw, ["risk_paths", "riskPaths", "data", "result"]) || raw || {};
    const summary = normalizeRiskPathSummary(valueFrom(body, ["summary"], {}));
    const paths = listFrom(body, ["paths", "items", "results", "data"]).map(normalizeRiskPath);
    const groups = listFrom(body, ["groups", "aggregates"]).map(normalizeRiskPathGroup);
    const trafficPaths = listFrom(body, ["traffic_paths", "trafficPaths"]).map(normalizeTrafficPath);
    return {
      available: true,
      summary,
      paths,
      groups,
      trafficPaths,
      total: numberValue(valueFrom(body, ["total"], paths.length)),
      groupsTotal: numberValue(valueFrom(body, ["groups_total", "groupsTotal"], groups.length)),
      trafficTotal: numberValue(valueFrom(body, ["traffic_count", "trafficCount", "traffic_total", "trafficTotal"], trafficPaths.length)),
      trafficCount: numberValue(valueFrom(body, ["traffic_count", "trafficCount"], trafficPaths.length)),
      count: numberValue(valueFrom(body, ["count"], paths.length)),
      raw: body,
    };
  }

  function normalizeRiskPathSummary(raw) {
    return {
      total: numberValue(valueFrom(raw, ["total"], 0)),
      anonymousPublicDataAccess: numberValue(valueFrom(raw, ["anonymous_public_data_access", "anonymousPublicDataAccess"], 0)),
      credentialDataAccess: numberValue(valueFrom(raw, ["credential_data_access", "credentialDataAccess"], 0)),
      credentialControlPlaneExposure: numberValue(valueFrom(raw, ["credential_control_plane_exposure", "credentialControlPlaneExposure"], 0)),
      publicTrafficExposure: numberValue(valueFrom(raw, ["public_traffic_exposure", "publicTrafficExposure"], 0)),
      directNetworkExposure: numberValue(valueFrom(raw, ["direct_network_exposure", "directNetworkExposure"], 0)),
      broadNetworkACL: numberValue(valueFrom(raw, ["broad_network_acl", "broadNetworkACL"], 0)),
      serviceCounts: normalizeCounts(valueFrom(raw, ["service_counts", "serviceCounts"], {})),
      severityCounts: normalizeCounts(valueFrom(raw, ["severity_counts", "severityCounts"], {})),
    };
  }

  function normalizeRiskPath(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id"])) || stableID(raw),
      pathType: stringValue(valueFrom(raw, ["path_type", "pathType", "type"], "")),
      severity: lower(valueFrom(raw, ["severity"], "unknown")),
      service: stringValue(valueFrom(raw, ["service"], "")),
      accountID: stringValue(valueFrom(raw, ["account_id", "accountId"], "")),
      provider: stringValue(valueFrom(raw, ["provider"], "")),
      region: stringValue(valueFrom(raw, ["region"], "")),
      source: normalizeRiskPathAsset(valueFrom(raw, ["source"], null)),
      target: normalizeRiskPathAsset(valueFrom(raw, ["target"], {})) || {},
      signals: listFrom(raw, ["signals"]).map((signal) => stringValue(signal)).filter(Boolean),
      evidence: valueFrom(raw, ["evidence"], {}),
    };
  }

  function normalizeRiskPathGroup(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id"])) || stableID(raw),
      pathType: stringValue(valueFrom(raw, ["path_type", "pathType", "type"], "")),
      severity: lower(valueFrom(raw, ["severity"], "unknown")),
      service: stringValue(valueFrom(raw, ["service"], "")),
      accountID: stringValue(valueFrom(raw, ["account_id", "accountId"], "")),
      provider: stringValue(valueFrom(raw, ["provider"], "")),
      region: stringValue(valueFrom(raw, ["region"], "")),
      source: normalizeRiskPathAsset(valueFrom(raw, ["source"], null)),
      targets: listFrom(raw, ["targets"]).map(normalizeRiskPathAsset).filter(Boolean),
      targetCount: numberValue(valueFrom(raw, ["target_count", "targetCount"], 0)),
      signals: listFrom(raw, ["signals"]).map((signal) => stringValue(signal)).filter(Boolean),
      evidence: valueFrom(raw, ["evidence"], {}),
    };
  }

  function normalizeRiskPathAsset(raw) {
    if (!raw) {
      return null;
    }
    return {
      id: stringValue(valueFrom(raw, ["id", "asset_id", "assetId"], "")),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"], "")),
      provider: stringValue(valueFrom(raw, ["provider"], "")),
      resource_type: stringValue(valueFrom(raw, ["resource_type", "resourceType"], "")),
      resource_id: stringValue(valueFrom(raw, ["resource_id", "resourceId"], "")),
      region: stringValue(valueFrom(raw, ["region"], "")),
      name: stringValue(valueFrom(raw, ["name"], "")),
    };
  }

  function normalizeTrafficPath(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id"], "")) || stableID(raw),
      pathType: stringValue(valueFrom(raw, ["path_type", "pathType"], "public_traffic_exposure")),
      severity: lower(valueFrom(raw, ["severity"], "unknown")),
      accountID: stringValue(valueFrom(raw, ["account_id", "accountId"], "")),
      provider: stringValue(valueFrom(raw, ["provider"], "")),
      region: stringValue(valueFrom(raw, ["region"], "")),
      entry: normalizeRiskPathAsset(valueFrom(raw, ["entry"], {})) || {},
      address: stringValue(valueFrom(raw, ["address"], "")),
      addressType: stringValue(valueFrom(raw, ["address_type", "addressType"], "")),
      listeners: listFrom(raw, ["listeners"]).map((listener) => ({
        port: stringValue(valueFrom(listener, ["port"], "")),
        protocol: stringValue(valueFrom(listener, ["protocol"], "")),
        status: stringValue(valueFrom(listener, ["status"], "")),
        aclStatus: stringValue(valueFrom(listener, ["acl_status", "aclStatus"], "")),
        aclType: stringValue(valueFrom(listener, ["acl_type", "aclType"], "")),
        aclOff: truthy(valueFrom(listener, ["acl_off", "aclOff"], false)),
      })),
      backends: listFrom(raw, ["backends"]).map((backend) => ({
        asset: normalizeRiskPathAsset(valueFrom(backend, ["asset"], null)),
        resourceID: stringValue(valueFrom(backend, ["resource_id", "resourceId"], "")),
        nativeID: stringValue(valueFrom(backend, ["native_id", "nativeId"], "")),
        name: stringValue(valueFrom(backend, ["name"], "")),
        port: stringValue(valueFrom(backend, ["port"], "")),
        weight: stringValue(valueFrom(backend, ["weight"], "")),
        status: stringValue(valueFrom(backend, ["status"], "")),
        securityGroups: listFrom(backend, ["security_groups", "securityGroups"]).map((group) => ({
          asset: normalizeRiskPathAsset(valueFrom(group, ["asset"], null)),
          resourceID: stringValue(valueFrom(group, ["resource_id", "resourceId"], "")),
          nativeID: stringValue(valueFrom(group, ["native_id", "nativeId"], "")),
          name: stringValue(valueFrom(group, ["name"], "")),
          policies: listFrom(group, ["policies"]).map(normalizeTrafficPolicy),
          openPolicies: listFrom(group, ["open_policies", "openPolicies"]).map(normalizeTrafficPolicy),
        })),
      })),
      cloudFirewallPolicies: listFrom(raw, ["cloud_firewall_policies", "cloudFirewallPolicies"]).map(normalizeTrafficFirewallPolicy),
      openPolicyCount: numberValue(valueFrom(raw, ["open_policy_count", "openPolicyCount"], 0)),
      cloudFirewallAllowCount: numberValue(valueFrom(raw, ["cloud_firewall_allow_count", "cloudFirewallAllowCount"], 0)),
      cloudFirewallDropCount: numberValue(valueFrom(raw, ["cloud_firewall_drop_count", "cloudFirewallDropCount"], 0)),
      missingBackendCount: numberValue(valueFrom(raw, ["missing_backend_count", "missingBackendCount"], 0)),
      missingSGCount: numberValue(valueFrom(raw, ["missing_security_group_count", "missingSecurityGroupCount", "missing_sg_count", "missingSGCount"], 0)),
      signals: listFrom(raw, ["signals"]).map((signal) => stringValue(signal)).filter(Boolean),
      evidence: valueFrom(raw, ["evidence"], {}),
    };
  }

  function normalizeScanRun(item) {
    const raw = item || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id", "scan_run_id", "scanRunId"])) || stableID(raw),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"])),
      provider: stringValue(valueFrom(raw, ["provider", "cloud", "vendor"])),
      status: lower(valueFrom(raw, ["status", "state"], "unknown")),
      started_at: valueFrom(raw, ["started_at", "startedAt", "created_at", "createdAt"]),
      finished_at: valueFrom(raw, ["finished_at", "finishedAt", "completed_at", "completedAt"]),
      summary: parseMaybeJSON(valueFrom(raw, ["summary", "stats", "result"], {})) || {},
      created_at: valueFrom(raw, ["created_at", "createdAt"]),
      updated_at: valueFrom(raw, ["updated_at", "updatedAt"]),
    };
  }

  function normalizeScanQuality(raw) {
    if (!raw) {
      return { available: false, summary: {}, runs: [], latestRun: null };
    }
    const body = firstRecord(raw, ["quality", "data", "result"]) || raw || {};
    const runs = listFrom(body, ["runs", "scan_runs", "scanRuns"]).map(normalizeQualityRun);
    const summary = normalizeQualitySummary(valueFrom(body, ["summary"], {}));
    return {
      available: true,
      summary,
      runs,
      latestRun: summary.latestRun || runs[0] || null,
      total: numberValue(valueFrom(body, ["total"], runs.length)),
      count: numberValue(valueFrom(body, ["count"], runs.length)),
      raw: body,
    };
  }

  function normalizeQualitySummary(raw) {
    const latestRaw = valueFrom(raw, ["latest_run", "latestRun"], null);
    return {
      totalRuns: numberValue(valueFrom(raw, ["total_runs", "totalRuns"], 0)),
      succeededRuns: numberValue(valueFrom(raw, ["succeeded_runs", "succeededRuns"], 0)),
      failedRuns: numberValue(valueFrom(raw, ["failed_runs", "failedRuns"], 0)),
      runningRuns: numberValue(valueFrom(raw, ["running_runs", "runningRuns"], 0)),
      assetsCollected: numberValue(valueFrom(raw, ["assets_collected", "assetsCollected"], 0)),
      findings: numberValue(valueFrom(raw, ["findings"], 0)),
      rules: numberValue(valueFrom(raw, ["rules"], 0)),
      evaluatedRules: numberValue(valueFrom(raw, ["evaluated_rules", "evaluatedRules"], 0)),
      skippedRules: numberValue(valueFrom(raw, ["skipped_rules", "skippedRules"], 0)),
      collectionFailures: numberValue(valueFrom(raw, ["collection_failures", "collectionFailures"], 0)),
      evaluationCoverage: numberValue(valueFrom(raw, ["evaluation_coverage", "evaluationCoverage"], 0)),
      collectionHealth: stringValue(valueFrom(raw, ["collection_health", "collectionHealth"], "unknown")),
      ruleQualityStatus: stringValue(valueFrom(raw, ["rule_quality_status", "ruleQualityStatus"], "")),
      ruleQuality: normalizeCoverageTotals(valueFrom(raw, ["rule_quality", "ruleQuality"], {})),
      failureCategories: normalizeCounts(valueFrom(raw, ["failure_categories", "failureCategories"], {})),
      failedResourceTypes: facetValues(valueFrom(raw, ["failed_resource_types", "failedResourceTypes"], [])),
      resourceTypes: normalizeQualityResourceTypes(valueFrom(raw, ["resource_type_drilldown", "resourceTypeDrilldown", "resourceTypes"], [])),
      latestRun: latestRaw ? normalizeQualityRun(latestRaw) : null,
    };
  }

  function normalizeQualityRun(raw) {
    return {
      id: stringValue(valueFrom(raw, ["id"], "")),
      account_id: stringValue(valueFrom(raw, ["account_id", "accountId"], "")),
      provider: stringValue(valueFrom(raw, ["provider"], "")),
      status: lower(valueFrom(raw, ["status"], "unknown")),
      started_at: valueFrom(raw, ["started_at", "startedAt"], ""),
      finished_at: valueFrom(raw, ["finished_at", "finishedAt"], ""),
      assets: numberValue(valueFrom(raw, ["assets"], 0)),
      findings: numberValue(valueFrom(raw, ["findings"], 0)),
      rules: numberValue(valueFrom(raw, ["rules"], 0)),
      evaluatedRules: numberValue(valueFrom(raw, ["evaluated_rules", "evaluatedRules"], 0)),
      skippedRules: numberValue(valueFrom(raw, ["skipped_rules", "skippedRules"], 0)),
      collectionFailures: numberValue(valueFrom(raw, ["collection_failures", "collectionFailures"], 0)),
      qualityStatus: stringValue(valueFrom(raw, ["quality_status", "qualityStatus"], "")),
      failureCategories: normalizeCounts(valueFrom(raw, ["failure_categories", "failureCategories"], {})),
      failedResourceTypes: facetValues(valueFrom(raw, ["failed_resource_types", "failedResourceTypes"], [])),
      resourceTypes: normalizeQualityResourceTypes(valueFrom(raw, ["resource_type_drilldown", "resourceTypeDrilldown", "resourceTypes"], [])),
      failureItems: listFrom(raw, ["failure_items", "failureItems"]),
    };
  }

  function normalizeQualityResourceTypes(raw) {
    return listFrom(raw, ["items", "resources", "resource_types", "resourceTypes", "data"]).map((item) => ({
      resourceType: stringValue(valueFrom(item, ["resource_type", "resourceType", "value", "label"], "")),
      status: stringValue(valueFrom(item, ["status"], "failed")),
      failures: numberValue(valueFrom(item, ["failures", "count"], 0)),
      categories: normalizeCounts(valueFrom(item, ["categories", "failure_categories", "failureCategories"], {})),
      regions: facetValues(valueFrom(item, ["regions"], [])),
      hint: stringValue(valueFrom(item, ["hint", "message"], "")),
    })).filter((item) => item.resourceType);
  }

  function normalizeRule(item) {
    const raw = item || {};
    const metadata = raw.metadata || {};
    return {
      _raw: raw,
      id: stringValue(valueFrom(raw, ["id", "rule_id", "ruleId"], metadata.id)) || stableID(raw),
      title: stringValue(valueFrom(raw, ["title", "name", "rule_name", "ruleName"], metadata.name || "")),
      severity: lower(valueFrom(raw, ["severity", "level"], metadata.severity || "unknown")),
      resource_type: stringValue(valueFrom(raw, ["resource_type", "resourceType", "asset_type", "assetType"], metadata.asset_type || metadata.service || "")),
      provider: stringValue(valueFrom(raw, ["provider"], metadata.provider || "")),
      status: lower(valueFrom(raw, ["status"], metadata.disabled ? "disabled" : "enabled")),
      enabled: valueFrom(raw, ["enabled"], !metadata.disabled),
    };
  }

  function normalizeCoverage(raw) {
    const body = firstRecord(raw, ["coverage", "data", "result"]) || raw || {};
    const totals = body.totals || body.summary || {};
    const resources = listFrom(body, ["resources", "items", "rows", "data"]);
    return {
      raw: body,
      resources,
      resourceTypes: numberValue(valueFrom(totals, ["resource_types", "resourceTypes"], resources.length)),
      totalRules: numberValue(valueFrom(totals, ["total_rules", "totalRules", "rules"], 0)),
      withExamples: numberValue(valueFrom(totals, ["with_examples", "withExamples"], 0)),
      missingDataRefs: numberValue(valueFrom(totals, ["missing_data_refs", "missingDataRefs"], 0)),
      disabled: numberValue(valueFrom(totals, ["disabled"], 0)),
      officialReviewed: numberValue(valueFrom(totals, ["official_reviewed", "officialReviewed"], 0)),
      needsReview: numberValue(valueFrom(totals, ["needs_review", "needsReview"], 0)),
      needsOfficialDocs: numberValue(valueFrom(totals, ["needs_official_docs", "needsOfficialDocs"], 0)),
      blocked: numberValue(valueFrom(totals, ["blocked"], 0)),
      needsLogicChange: numberValue(valueFrom(totals, ["needs_logic_change", "needsLogicChange"], 0)),
      withRemediation: numberValue(valueFrom(totals, ["with_remediation", "withRemediation"], 0)),
      missingRemediation: numberValue(valueFrom(totals, ["missing_remediation", "missingRemediation"], 0)),
      verifiedResources: numberValue(valueFrom(totals, ["verified_resources", "verifiedResources"], 0)),
      missingSampleRefs: numberValue(valueFrom(totals, ["missing_sample_refs", "missingSampleRefs"], 0)),
      missingSampleGroups: numberValue(valueFrom(totals, ["missing_sample_groups", "missingSampleGroups"], 0)),
    };
  }

  function normalizeCoverageTotals(raw) {
    const totals = raw || {};
    return {
      totalRules: numberValue(valueFrom(totals, ["total_rules", "totalRules", "rules"], 0)),
      missingDataRefs: numberValue(valueFrom(totals, ["missing_data_refs", "missingDataRefs"], 0)),
      officialReviewed: numberValue(valueFrom(totals, ["official_reviewed", "officialReviewed"], 0)),
      needsReview: numberValue(valueFrom(totals, ["needs_review", "needsReview"], 0)),
      needsOfficialDocs: numberValue(valueFrom(totals, ["needs_official_docs", "needsOfficialDocs"], 0)),
      blocked: numberValue(valueFrom(totals, ["blocked"], 0)),
      needsLogicChange: numberValue(valueFrom(totals, ["needs_logic_change", "needsLogicChange"], 0)),
      withRemediation: numberValue(valueFrom(totals, ["with_remediation", "withRemediation"], 0)),
      missingRemediation: numberValue(valueFrom(totals, ["missing_remediation", "missingRemediation"], 0)),
      verifiedResources: numberValue(valueFrom(totals, ["verified_resources", "verifiedResources"], 0)),
      missingSampleRefs: numberValue(valueFrom(totals, ["missing_sample_refs", "missingSampleRefs"], 0)),
      missingSampleGroups: numberValue(valueFrom(totals, ["missing_sample_groups", "missingSampleGroups"], 0)),
    };
  }

  function normalizeRuntime(raw) {
    const body = firstRecord(raw, ["runtime", "data", "result"]) || raw || {};
    return {
      raw: body,
      status: lower(valueFrom(body, ["status", "health", "state"], raw ? "ok" : "unknown")),
      version: stringValue(valueFrom(body, ["version", "build", "commit"], "")),
      mode: stringValue(valueFrom(body, ["mode", "env", "environment"], "")),
      provider: stringValue(valueFrom(body, ["provider"], "")),
      api: stringValue(valueFrom(body, ["api", "endpoint"], "")),
      database: stringValue(valueFrom(body, ["database_path", "databasePath", "database", "db", "store"], "")),
      rulesDir: stringValue(valueFrom(body, ["rules_dir", "rulesDir", "rules", "rule_path", "rulePath"], "")),
      rulesAvailable: Boolean(valueFrom(body, ["rules_available", "rulesAvailable"], false)),
      checked_at: new Date().toISOString(),
    };
  }

  function normalizeGraph(raw) {
    const body = firstRecord(raw, ["graph", "data", "result"]) || raw || {};
    const nodes = listFrom(body, ["nodes", "vertices"]).map((node) => ({
      id: stringValue(valueFrom(node, ["id", "resource_id", "resourceId"])) || stableID(node),
      label: stringValue(valueFrom(node, ["label", "name", "resource_id", "id"], "node")),
      type: stringValue(valueFrom(node, ["type", "resource_type", "resourceType"], "")),
    }));
    const edges = listFrom(body, ["edges", "links", "relationships"]).map((edge) => ({
      source: stringValue(valueFrom(edge, ["source", "source_id", "sourceId", "source_resource_id", "sourceResourceId"])),
      target: stringValue(valueFrom(edge, ["target", "target_id", "targetId", "target_resource_id", "targetResourceId"])),
      type: stringValue(valueFrom(edge, ["type", "relationship_type", "relationshipType"], "related_to")),
    }));
    if (!nodes.length && edges.length) {
      return graphFromRelationships(edges.map((edge) => normalizeRelationship(edge)));
    }
    return { nodes, edges };
  }

  function graphFromRelationships(relationships) {
    const nodes = new Map();
    const edges = [];
    relationships.forEach((item) => {
      const source = item.source_resource_id || item.source_asset_id;
      const target = item.target_resource_id;
      if (!source || !target) {
        return;
      }
      nodes.set(source, { id: source, label: source, type: item.source_resource_type });
      nodes.set(target, { id: target, label: target, type: "target" });
      edges.push({ source, target, type: item.relationship_type });
    });
    return { nodes: Array.from(nodes.values()), edges };
  }

  function listFrom(body, keys) {
    const value = parseMaybeJSON(body);
    if (!value) {
      return [];
    }
    if (Array.isArray(value)) {
      return value;
    }
    for (const key of keys) {
      const candidate = value[key];
      if (Array.isArray(candidate)) {
        return candidate;
      }
      if (candidate && Array.isArray(candidate.items)) {
        return candidate.items;
      }
    }
    if (value.data && typeof value.data === "object") {
      return listFrom(value.data, keys);
    }
    return [];
  }

  function firstRecord(body, keys) {
    const value = parseMaybeJSON(body);
    if (!value || Array.isArray(value) || typeof value !== "object") {
      return null;
    }
    for (const key of keys) {
      const candidate = parseMaybeJSON(value[key]);
      if (candidate && !Array.isArray(candidate) && typeof candidate === "object") {
        return candidate;
      }
      if (Array.isArray(candidate) && candidate.length) {
        return candidate[0];
      }
    }
    if (value.data && typeof value.data === "object" && !Array.isArray(value.data)) {
      return firstRecord(value.data, keys) || value.data;
    }
    return value;
  }

  function valueFrom(source, keys, fallback) {
    if (!source || typeof source !== "object") {
      return fallback;
    }
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null) {
        return source[key];
      }
    }
    return fallback;
  }

  function normalizeCounts(value) {
    const counts = {};
    if (!value) {
      return counts;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => {
        const label = lower(valueFrom(item, ["label", "value", "severity", "name"], ""));
        counts[label] = numberValue(valueFrom(item, ["count", "total", "value"], 0));
      });
      return counts;
    }
    if (typeof value === "object") {
      Object.entries(value).forEach(([key, count]) => {
        counts[lower(key)] = numberValue(count);
      });
    }
    return counts;
  }

  function facetValues(value) {
    if (!value) {
      return [];
    }
    if (Array.isArray(value)) {
      return value.map((item) => {
        if (item && typeof item === "object") {
          return {
            label: stringValue(valueFrom(item, ["label", "value", "name", "id"], "unknown")),
            count: numberValue(valueFrom(item, ["count", "total"], 0)),
          };
        }
        return { label: stringValue(item), count: 0 };
      }).filter((item) => item.label);
    }
    if (typeof value === "object") {
      return Object.entries(value)
        .map(([label, count]) => ({ label, count: numberValue(count) }))
        .filter((item) => item.label);
    }
    return [{ label: stringValue(value), count: 0 }];
  }

  function facetFromValues(values) {
    return Object.entries(values.reduce((acc, value) => {
      const label = stringValue(value || "unknown");
      if (label) {
        acc[label] = (acc[label] || 0) + 1;
      }
      return acc;
    }, {}))
      .sort((a, b) => b[1] - a[1])
      .map(([label, count]) => ({ label, count }));
  }

  function countBy(items, key) {
    return items.reduce((acc, item) => {
      const label = lower(item[key] || "unknown");
      acc[label] = (acc[label] || 0) + 1;
      return acc;
    }, {});
  }

  function unique(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function sameID(left, right) {
    return Boolean(left && right && left.id && right.id && left.id === right.id);
  }

  function stableID(value) {
    const raw = JSON.stringify(value || {});
    let hash = 0;
    for (let index = 0; index < raw.length; index += 1) {
      hash = ((hash << 5) - hash + raw.charCodeAt(index)) | 0;
    }
    return "local-" + Math.abs(hash);
  }

  function cacheItem(kind, item) {
    const key = `${kind}:${item.id || item.resource_id || item.rule_id || state.detailIndex.size}`;
    state.detailIndex.set(key, { kind, item });
    return key;
  }

  function compact(value) {
    return Object.entries(value || {}).reduce((acc, [key, entry]) => {
      if (entry !== undefined && entry !== null && String(entry).trim() !== "") {
        acc[key] = entry;
      }
      return acc;
    }, {});
  }

  function parseJSON(text) {
    if (!text) {
      return {};
    }
    try {
      return JSON.parse(text);
    } catch (error) {
      return { raw: text };
    }
  }

  function parseMaybeJSON(value) {
    if (typeof value !== "string") {
      return value;
    }
    const trimmed = value.trim();
    if (!trimmed || !/^[\[{]/.test(trimmed)) {
      return value;
    }
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      return value;
    }
  }

  function errorMessage(body, fallback) {
    if (body && typeof body === "object") {
      return body.error || body.message || body.detail || fallback;
    }
    return fallback;
  }

  function routeFromHash() {
    const raw = window.location.hash.replace(/^#\/?/, "").split("?")[0] || "overview";
    if (raw === "topology") {
      return "relationships";
    }
    return routes[raw] ? raw : "overview";
  }

  function translateStaticShell() {
    document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      node.textContent = t(node.dataset.i18n, node.textContent);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder, node.getAttribute("placeholder") || ""));
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach((node) => {
      node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel, node.getAttribute("aria-label") || ""));
    });
    translateSelectOptions(el.inputs.severity, "severity");
    translateSelectOptions(el.inputs.status, "status");
    populateResourceTypeOptions(state.facets);
    el.languageButtons.forEach((button) => {
      button.classList.toggle("active", normalizeLanguage(button.dataset.lang) === state.language);
    });
    el.title.textContent = routeLabel(state.route);
    setActiveNav();
  }

  function translateSelectOptions(select, namespace) {
    if (!select) {
      return;
    }
    Array.from(select.options).forEach((option) => {
      option.textContent = option.value ? translateValue(namespace, option.value) : t("filters.all");
    });
  }

  function populateResourceTypeOptions(facets) {
    const select = el.inputs.resource_type;
    if (!select) {
      return;
    }
    const selected = state.filters.resource_type || select.value || "";
    const grouped = groupedResourceTypes(facets);
    select.innerHTML = "";
    select.appendChild(new Option(t("filters.all"), ""));
    resourceTypeGroups.forEach((group) => {
      const items = grouped.get(group.key) || [];
      if (!items.length) {
        return;
      }
      const optgroup = document.createElement("optgroup");
      optgroup.label = state.language === "zh" ? group.zh : group.en;
      items.forEach((item) => {
        optgroup.appendChild(new Option(resourceTypeOptionLabel(item), item.label));
      });
      select.appendChild(optgroup);
    });
    if (selected && Array.from(select.options).some((option) => option.value === selected)) {
      select.value = selected;
    } else {
      select.value = "";
    }
    state.filters.resource_type = select.value;
  }

  function groupedResourceTypes(facets) {
    const byLabel = new Map();
    resourceTypeGroups.forEach((group) => {
      group.values.forEach((label) => {
        byLabel.set(label, { label, count: 0, group: group.key });
      });
    });
    (facets && facets.resourceTypes ? facets.resourceTypes : []).forEach((item) => {
      const label = stringValue(item.label || item.value || item.name || item);
      if (!label) {
        return;
      }
      byLabel.set(label, {
        label,
        count: numberValue(item.count),
        group: resourceTypeGroupKey(label),
      });
    });

    const grouped = new Map(resourceTypeGroups.map((group) => [group.key, []]));
    Array.from(byLabel.values())
      .sort((left, right) => resourceTypeSort(left, right))
      .forEach((item) => {
        const key = item.group || "other";
        grouped.set(key, [...(grouped.get(key) || []), item]);
      });
    return grouped;
  }

  function resourceTypeGroupKey(value) {
    const type = canonicalType(value);
    if (type === "ecs" || type.includes("instance")) {
      return "compute";
    }
    if (["slb", "alb", "nlb"].includes(type) || type.includes("loadbalancer") || type.includes("securitygroup")) {
      return "network";
    }
    if (dataAssetType(value) || type.includes("database")) {
      return "data";
    }
    if (type.includes("ram") || type.includes("role") || type.includes("user") || type === "account") {
      return "identity";
    }
    return "other";
  }

  function resourceTypeSort(left, right) {
    if (left.count !== right.count) {
      return right.count - left.count;
    }
    return left.label.localeCompare(right.label);
  }

  function resourceTypeOptionLabel(item) {
    if (item.count) {
      return `${item.label} (${number(item.count)})`;
    }
    return item.label;
  }

  function translateValue(namespace, value) {
    if (state.language !== "zh") {
      return String(value || "");
    }
    const dictionaries = {
      severity: {
        critical: "严重",
        high: "高危",
        medium: "中危",
        low: "低危",
        info: "提示",
        unknown: "未知",
      },
      status: {
        open: "未修复",
        resolved: "已修复",
        suppressed: "已忽略",
        running: "运行中",
        succeeded: "成功",
        failed: "失败",
        enabled: "启用",
        disabled: "禁用",
        "not called": "未调用",
        unknown: "未知",
        ok: "正常",
      },
    };
    return (dictionaries[namespace] && dictionaries[namespace][lower(value)]) || String(value || "");
  }

  function localPhrase(value) {
    const text = String(value || "");
    return state.language === "zh" ? (zhPhrases[text] || text) : text;
  }

  function localizeRenderedText(root) {
    if (state.language !== "zh" || !root) {
      return;
    }
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
      nodes.push(walker.currentNode);
    }
    nodes.forEach((node) => {
      const text = node.nodeValue || "";
      const trimmed = text.trim();
      const translated = zhPhrases[trimmed];
      if (translated) {
        node.nodeValue = text.replace(trimmed, translated);
      }
    });
  }

  function setActiveNav() {
    el.nav.querySelectorAll("a").forEach((link) => {
      const route = link.dataset.route;
      const mark = link.querySelector("span");
      const label = link.querySelector("em");
      if (mark) {
        mark.textContent = routeInitial(route);
      }
      if (label) {
        label.textContent = routeLabel(route);
      }
      link.classList.toggle("active", route === state.route);
    });
  }

  function setStatus(message) {
    el.status.textContent = message;
  }

  function syncFiltersFromDOM() {
    Object.entries(el.inputs).forEach(([key, input]) => {
      state.filters[key] = String(input.value || "").trim();
    });
    if (!state.filters.limit) {
      state.filters.limit = "50";
    }
  }

  function syncDOMFromFilters() {
    Object.entries(el.inputs).forEach(([key, input]) => {
      input.value = state.filters[key] || "";
    });
  }

  function titleFor(kind, item) {
    if (kind === "finding") {
      return item.title || item.rule_id || "Finding";
    }
    if (kind === "asset") {
      return item.name || item.resource_id || item.id || "Asset";
    }
    if (kind === "relationship") {
      return item.relationship_type || "Relationship";
    }
    if (kind === "scan") {
      return item.id || "Scan run";
    }
    if (kind === "rule") {
      return item.title || item.id || "Rule";
    }
    return "Details";
  }

  function kindLabel(kind) {
    if (state.language !== "zh") {
      return kind;
    }
    return {
      finding: "风险",
      asset: "资产",
      relationship: "拓扑关系",
      scan: "扫描",
      rule: "规则",
    }[kind] || kind;
  }

  function severityChip(severity, count) {
    const value = lower(severity || "unknown");
    const suffix = count === undefined ? "" : ` <strong>${number(count)}</strong>`;
    return `<span class="chip ${escapeHTML(value)}">${escapeHTML(translateValue("severity", value))}${suffix}</span>`;
  }

  function statusChip(status) {
    const value = lower(status || "unknown");
    return `<span class="chip ${escapeHTML(value)}">${escapeHTML(translateValue("status", value))}</span>`;
  }

  function chip(label, count) {
    const text = stringValue(label || "unknown");
    const suffix = count === undefined || count === "" ? "" : ` <strong>${number(count)}</strong>`;
    return `<span class="chip">${escapeHTML(text)}${suffix}</span>`;
  }

  function qualityRatio(done, total) {
    const value = numberValue(done);
    const denominator = numberValue(total);
    if (!denominator) {
      return chip("0/0");
    }
    return chip(`${number(value)}/${number(denominator)}`);
  }

  function collectorFieldChip(status, missingRefs) {
    const value = stringValue(status || "unknown");
    const count = numberValue(missingRefs);
    return count > 0 ? chip(localPhrase(value), count) : chip(localPhrase(value));
  }

  function coverageReviewCell(row) {
    const markers = [];
    if (numberValue(row.blocked) > 0) {
      markers.push(chip(localPhrase("blocked"), row.blocked));
    }
    if (numberValue(row.needs_logic_change) > 0) {
      markers.push(chip(localPhrase("needs_logic_change"), row.needs_logic_change));
    }
    return `${qualityRatio(row.official_reviewed, row.total_rules)}${markers.length ? `<div class="chips compact-chips">${markers.join("")}</div>` : ""}`;
  }

  function number(value) {
    if (value === "" || value === undefined || value === null) {
      return "";
    }
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed.toLocaleString();
    }
    return escapeHTML(String(value));
  }

  function numberValue(value) {
    if (value && typeof value === "object") {
      return numberValue(value.count || value.total || value.value || 0);
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function stringValue(value) {
    if (value === undefined || value === null) {
      return "";
    }
    if (typeof value === "string") {
      return value;
    }
    return String(value);
  }

  function lower(value) {
    return stringValue(value).trim().toLowerCase();
  }

  function escapeRegExp(value) {
    return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function truthy(value) {
    if (value === true) {
      return true;
    }
    if (value === false || value === undefined || value === null) {
      return false;
    }
    return ["true", "yes", "y", "1", "on", "enabled", "enable"].includes(lower(value));
  }

  function displayValue(value) {
    const parsed = parseMaybeJSON(value);
    if (parsed && typeof parsed === "object") {
      return JSON.stringify(parsed);
    }
    return parsed === undefined || parsed === null ? "" : String(parsed);
  }

  function formatDate(value) {
    if (!value) {
      return "";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    try {
      return new Intl.DateTimeFormat(undefined, {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short",
      }).format(date);
    } catch {
      return date.toLocaleString();
    }
  }

  function durationBetween(start, end) {
    if (!start || !end) {
      return "";
    }
    const startDate = new Date(start);
    const endDate = new Date(end);
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
      return "";
    }
    const seconds = Math.max(0, Math.round((endDate.getTime() - startDate.getTime()) / 1000));
    if (seconds < 60) {
      return `${seconds}s`;
    }
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    if (minutes < 60) {
      return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const minuteRest = minutes % 60;
    return minuteRest ? `${hours}h ${minuteRest}m` : `${hours}h`;
  }

  function shortRunID(value) {
    const text = stringValue(value);
    if (text.length <= 12) {
      return text || "unknown";
    }
    return `${text.slice(0, 8)}...${text.slice(-4)}`;
  }

  function shortLabel(value) {
    const text = stringValue(value);
    if (text.length <= 8) {
      return text;
    }
    const parts = text.split(/[/:._-]/).filter(Boolean);
    return (parts[parts.length - 1] || text).slice(0, 8);
  }

  function escapeHTML(value) {
    return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[char]);
  }

  boot();
})();
