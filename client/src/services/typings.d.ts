declare namespace API {
  interface Result {
    code: number;
    errorCode: string;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<Record<string, any>>;
      total?: number;
    };
  }

  interface Result_List {
    code: number;
    errorCode: string;
    errorMsg: string;
    msg: string;
    content: Array<Record<string, any>>;
  }

  interface Result_String_ {
    msg?: string;
    code?: number;
    content?: string;
    errorCode?: string;
    errorMsg?: string;
  }

  interface Result_Number_ {
    msg?: string;
    code?: number;
    content?: number;
    errorCode?: string;
    errorMsg?: string;
  }

  interface Result_T_ {
    msg?: string;
    code?: number;
    errorCode: string;
    errorMsg: string;
    content?: any;
  }

  /** Rule Group */
  interface RuleGroupInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    /** Rule group name */
    groupName?: string;
    /** Rule group description */
    groupDesc?: string;
    /** High risk count */
    highLevelRiskCount?: number;
    /** Medium risk count */
    mediumLevelRiskCount?: number;
    /** Low risk count */
    lowLevelRiskCount?: number;
    /** Creator Name */
    username?: string;
    /** Number of rules */
    ruleCount?: string;
    /** Last scan start time */
    lastScanStartTime?: string;
    /** Last scan end time */
    lastScanEndTime?: string;
  }

  /** Rule group results */
  interface Result_RuleGroupInfo_ {
    code: number;
    success: boolean;
    content: {
      data: Array<RuleGroupInfo>;
      total: number;
    };
  }

  type RiskLevelEnum = 'High' | 'Medium' | 'Low';

  /** rule list */
  interface RuleProjectInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    lastScanTime?: string;
    /** Rule Group */
    groupName?: string;
    /** Rule group ID */
    ruleGroupId?: number;
    /** Rule Name */
    ruleName?: string;
    /** Risk level */
    riskLevel?: RiskLevelEnum;
    /** platform */
    platform?: string;
    /** Resource type */
    resourceType?: string;
    /** Rule description */
    ruleDesc?: string;
    /** Number of risks */
    riskCount?: number;
    /** running status  */
    isRunning?: number;
    /** Disabled state */
    status?: string;
    /** Repair suggestions */
    advice?: string;
    /** Fix Link */
    link?: string;
    /** Risk Context Template */
    context?: string;
    /** Rego rules */
    ruleRego?: string;
    /** Rule Type **/
    ruleTypeNameList?: Array<string>;
    /** Resource type **/
    resourceTypeStr?: string;
    /** List of global variable configuration IDs **/
    globalVariableConfigIdList?: Array<number>;
    /** Create personnel **/
    username?: string;
    /** Rule Code **/
    ruleCode?: string;
    /** Rule Group Name List */
    ruleGroupNameList?: Array<string>;
    /** Whether the rule is selected by current tenant */
    tenantSelected?: boolean;
    /** List of tenant names that have selected this rule */
    selectedTenantNameList?: Array<string>;
  }

  /** Platform Results */
  interface Result_PlatformInfo_ {
    success: boolean;
    content: Array<Record<string, any>>;
    message: string;
    total: number;
  }

  /** Edit rule details result */
  interface Result_RegoInfo_ {
    isisDraft?: boolean;
    ruleRego?: string;
    input?: string;
    ruleId?: number;
    page?: number;
    size?: number;
    globalVariableConfigIdList?: Array<number>;
    type?: 'TENANT' | 'CLOUD_ACCOUNT' | 'INPUT';
    selectId?: number;
    platform?: string;
    resourceType?: string;
  }

  interface UserInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    lastLoginTime?: string;
    username?: string;
    password?: string;
    userId?: string;
    status?: string;
    tenantId?: number;
    tenantName?: string;
    roleName?: string;
    selectTenantRoleName?: string;
    token?: string;
    tenantIds?: string;
    code?: string;
    inviteCode?: string;
  }

  interface TenantInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    tenantName?: string;
    status?: string;
    tenantDesc?: string;
    memberCount?: number;
    tenantId?: number;
    pageLimit?: boolean;
    disable?: boolean;
  }

  interface AgentInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    registryValue?: string;
    registryTime?: string;
    cron?: string;
    status?: string;
    agentName?: string;
    platform?: string;
    onceToken?: string;
    ruleNameList?: Array<string>;
  }

  interface TenantUser {
    userId: string;
    tenantId: number;
  }

  interface CloudAccountResult {
    page?: number;
    size?: number;
    platformList?: Array<string>;
    cloudAccountId?: string;
    alias?: string;
    status?: string;
    id?: number;
    gmtCreate?: string;
    gmtModified?: string;
    ak?: string;
    sk?: string;
    platform?: string;
    platformName?: string;
    tenantId?: number;
    tenantName?: string;
    resourceCount?: number;
    riskCount?: number;
    lastScanTime?: string;
    resourceTypeList?: Array<string>;
    collectorStatus?: string;
    accountStatus?: string;
    onceToken?: string;
    changeTenantPermission?: boolean; // have permission to modify tenants
    credentialsJson?: string;
    credentialsObj?: Record<string, any>;
    site?: string;
    owner?: string;
    projectId?: string;
    proxyConfig?: string;
  }

  interface RiskInfo {
    id?: number;
    page?: number; // PageNumber
    size?: number; // PageSize
    ruleName?: string; // Rule Name
    ruleGroupIdList?: Array<number>; // List of Rule Group IDs
    cloudAccountId?: string; // Cloud account ID
    resourceId?: string; // Resource ID
    resourceName?: string; // Resource Name
    riskLevelList?: Array<string>; // Risk level
    platformList?: Array<string>; // Platform
    resourceTypeList?: Array<string>; // Asset Type
    status?: string; // Risk status
    ignoreReasonTypeList?: Array<string>; // Ignore type MISREPORT, EXCEPTION, IGNORE;
    riskId?: string | number; // Risk ID
    ignoreReasonType?: string;
    ignoreReason?: string;
    notes?: string; // Comment information
    ruleIdList?: Array<number>;
  }

  interface BaseRiskResultInfo {
    icon?: string;
    gmtCreate?: string; // Creation time
    gmtModified?: string; // Last scan hit
    id?: number;
    ruleId?: number; // Rule ID
    cloudAccountId?: string; // Cloud account ID
    alias?: string; // Cloud account alias
    resourceId?: string; // Resource ID
    resourceName?: string; // Resource Name
    updateTime?: string; // Update time
    platform?: string; // Platform
    resourceType?: string; // Asset Type
    result?: string; // Detailed information of scanning results
    region?: string; // Regional information
    tenantId?: number; // Tenant ID
    status?: string; // State
    ruleSnapshoot?: string; // Rule snapshot
    resourceSnapshoot?: string; // Asset snapshot
    resourceInstance?: string; // Latest asset data
    ignoreReasonType?: string; // Types of ignored reasons
    ignoreReason?: string; // Reasons for Neglecting
    resourceExist?: boolean; // Does the current resource exist
    resourceStatus?: 'exist' | 'not_exist';
    ruleTypeNameList?: Array<string>; // Rule Type
    ruleVO: {
      // Information on association rules
      id: number;
      gmtCreate: string;
      gmtModified: string;
      lastScanTime: string; // Last scan time
      ruleGroupId: string;
      ruleName?: string;
      riskLevel?: string;
      platform?: string;
      resourceType?: string;
      ruleRegoId?: number;
      userId?: string;
      ruleDesc?: string; // Rule description
      groupName?: string;
      advice?: string; // Repair suggestions
      link?: string; // Reference link
    };
  }

  interface Result_RiskInfo {
    code: number;
    content: {
      data: Array<BaseRiskResultInfo>;
      total: number;
    };
    errorCode: number;
    errorMsg: string;
    msg: string;
  }

  interface BaseRiskLogInfo {
    id: number;
    gmtCreate: string;
    gmtModified: string;
    userId: string; // User id
    username: string; // User name
    action: string; // Action
    correlationId: number; // Correlation ID
    notes: string; // Notes
  }

  interface Result_RiskLogInfo {
    code: number;
    content: Array<BaseRiskLogInfo>;
    errorCode: number;
    errorMsg: string;
    msg: string;
  }

  interface AssetConfig {
    BASE_INFO: {
      [key: string]: any;
    };
    NETWORK: {
      [key: string]: any;
    };
  }

  interface AssetInfo {
    id?: number | string;
    page?: number;
    size?: number;
    scrollId?: string;
    platform?: string; // Platform
    resourceType?: string; // Resource type
    resourceTypeList?: any[];
    cloudAccountId?: string; // Cloud account ID
    platformList?: Array<string>; // Platform List
    address?: string; // Address
    resourceName?: string; // Resource Name
    resourceId?: string; // Resource ID
    filterFieldName?: string; // Filter field names
    gmtCreate?: string;
    gmtModified?: string;
    status?: 'valid' | 'invalid';
    path?: string; // Route
    name?: string; // Name
    value?: string; // Value
    searchParam?: string; // Resource Name | id Filter shared fields
    idList?: Array<number>;
  }

  interface BaseAssetResultInfo {
    id: string;
    gmtCreate: string;
    gmtModified: string;
    resourceType: string; // Resource type
    resourceName: string; // Resource Name
    resourceId: string; // Resource ID
    platform: string; // Platform
    cloudAccountId: string; // Cloud Account ID
    alias: string; // Cloud account alias
    inChina: boolean; // Is it domestic
    tenantId: string; // Tenant ID
    tenantName: string; // Tenant Name
    regionId: string; // Region
    address: string; // Address
    instance: {
      // Instance object
      [key: string]: any;
    };
    highLevelRiskCount?: number; // High risk quantity
    mediumLevelRiskCount?: number; // Medium risk quantity
    lowLevelRiskCount?: number; // Low risk quantity
    rulePassRate?: string; // Strategy pass rate
    resourceDetailConfigMap?: Record<string, Array<any>>; // Configuration details
  }

  interface Result_AssetInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<BaseAssetResultInfo>;
      total: number;
      scrollId?: string;
    };
  }

  interface BaseAggregateAssetInfo {
    // Platform
    platform: string;
    // Number of resources
    count: number;
    // Resource type
    resourceType: any[] | string;
    // Resource name, use carefully resourceTypeName
    resourceTypeName: string;
    // High risk numbers
    highLevelRiskCount: number;
    // Medium risk numbers
    mediumLevelRiskCount: number;
    // Low risk numbers
    lowLevelRiskCount: number;
    typeFullNameList: any[];
    // Latest resource information
    latestResourceInfo: {
      // Resource ID
      resourceId: string;
      // Resource Name
      resourceName: string;
      // Change time
      gmtModified: string;
      // Address, not all resources have addresses
      address: null;
    };
  }

  interface Result_AggregateAssetInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<BaseAggregateAssetInfo>;
      total: number;
      scrollId: string;
    };
  }

  interface Result_AggregateAssetInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseAssetResultInfo>;
  }

  interface Result_AssetFieldInfo {
    code: number;
    content: Array<string>;
    errorCode: number;
    errorMsg: string;
    msg: string;
  }

  interface Result_AssetDetailInfo {
    code: number;
    errorCode: string;
    errorMsg: string;
    msg: string;
    content: BaseAssetResultInfo;
  }

  interface Result_AssetTypeInfo {
    code: number;
    content: Array<AssetInfo>;
    errorCode: number;
    errorMsg: string;
    msg: string;
  }

  interface BaseAssetRiskQuantityInfo {
    id: number;
    totalRiskCount: number;
    highLevelRiskCount: number;
    mediumLevelRiskCount: number;
    lowLevelRiskCount: number;
  }

  interface Result_AssetRiskQuantity {
    code: number;
    errorCode: string;
    errorMsg: string;
    msg: string;
    content: Array<BaseAssetRiskQuantityInfo>;
  }

  interface InvolveInfo {
    page?: number;
    size?: number;
    id?: number;
    gmtCreate?: string; // Creation time
    gmtModified?: string; // Update time
    name?: string; // Title
    actionType?: string; // Subscription type
    username?: string; // Founder
    status?: string;
    actionList?: Array<any>;
    ruleConfig?: Array<any>;
  }

  interface Result_InvolveInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<InvolveInfo>;
      total: number;
    };
  }

  interface BaseYesterdayHomeAggregatedDataVO {
    cloudAccountCount: number;
    platformCount: number;
    resourceCount: number;
    riskCount: number;
    yesterdayHomeAggregatedDataVO?: BaseYesterdayHomeAggregatedDataVO;
  }

  interface BaseAggregatedInfo {
    cloudAccountCount: number; // Cloud account
    platformCount: number; // Cloud platform
    resourceCount: number; // Natural resources
    riskCount: number; // Risk
    yesterdayHomeAggregatedDataVO: BaseYesterdayHomeAggregatedDataVO;
  }

  interface Result_AggregatedInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: BaseAggregatedInfo;
  }

  interface BaseRiskLevelInfo {
    lowLevelRiskCount: number;
    mediumLevelRiskCount: number;
    highLevelRiskCount: number;
  }

  interface Result_RiskLevelInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: BaseRiskLevelInfo;
  }

  interface BaseAccessKeyInfo {
    accessKeyExistAclCount: number;
    accessKeyNotExistAclCount: number;
    accessKeyCount: 0;
    platform?: string;
  }

  interface Result_AccessKeyInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseAccessKeyInfo>;
  }

  interface BaseRiskRecordInfo {
    ruleId: number;
    ruleName: string;
    ruleCode?: string;
    ruleTypeNameList: Array<string>;
    riskLevel: string;
    count: number;
    platform: string;
  }

  interface Result_RiskRecordInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseRiskRecordInfo>;
  }

  interface BaseRiskTrendInfo {
    date: string;
    type: string;
    count: number;
  }

  interface Result_RiskTrendInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseRiskTrendInfo>;
  }

  interface BaseAggregatedInfo {
    total: number;
    platform: string;
    resouceDataList: Array<{
      resourceType: string;
      count: number;
      resourceGroupType: string;
      resourceGroupTypeName: string;
      icon: string;
    }>;
  }

  interface Result_ResourceInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseAggregatedInfo>;
  }

  interface GlobalVariableConfigInfo {
    id?: number;
    page?: number;
    size?: number;
    gmtCreate?: string;
    gmtModified?: string;
    name?: string;
    path?: string;
    username?: string;
    userId?: string;
    version?: string;
    status?: string;
    data?: string;
    ruleNameList?: Array<any>;
  }

  interface BaseAccessInfo {
    id?: number;
    gmtCreate?: string;
    gmtModified?: string;
    userId?: string;
    accessKey?: string;
    secretKey?: string;
    remark?: string;
  }

  interface Result_AccessInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseAccessInfo>;
  }

  interface BaseWhiteListRuleInfo {
    id?: number;
    ruleType?: 'RULE_ENGINE' | 'REGO';
    ruleName?: string;
    ruleContent?: string;
    ruleDesc?: string;
    status?: string;
    actionList?: Array<any>;
    condition?: string;
    regoContent?: string;
    creator?: string;
    lockHolder?: string;
    enable?: 1 | 0;
    page?: number;
    size?: number;
    riskRuleCode?: string;
    creatorName?: string;
    lockHolderName?: string;
    isLockHolder?: string;
    input?: string;
    riskId?: string | number;
  }

  interface BaseProductPosture {
    productType?: string;
    version?: string;
    policy?: string;
    policyDetail?: string;
    status?: 'close' | 'open';
    protectedResourcePercent?: string;
    protectedCount?: number;
    total?: number;
  }

  interface BaseSecurityInfo {
    page?: number;
    size?: number;
    platform?: string;
    cloudAccountId?: string;
    alias?: string;
    tenantName?: string;
    total?: number;
    securityProductPostureMap?: {
      FIREWALL: 'close' | 'open';
      SAS: 'close' | 'open';
      DDoS: 'close' | 'open';
      WAF: 'close' | 'open';
    };
    gmtModified?: string;
    gmtCreate?: string;
    productPostureList?: Array<BaseProductPosture>;
    statusMap?: { [key: string]: string };
  }

  interface Result_SecurityInfo {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<BaseSecurityInfo>;
      total: number;
    };
  }

  interface BaseRiskCard {
    page?: number;
    size?: number;
    cloudAccountId?: string;
    platformList?: Array<string>;
    ruleTypeIdList?: Array<number[]>;
    id?: number;
    gmtCreate?: string;
    gmtModified?: string;
    lastScanTime?: string;
    ruleName?: string;
    ruleGroupList?: Array<any>;
    riskLevel?: string;
    platform?: string;
    resourceType?: string;
    resourceTypeStr?: string;
    resourceTypeGroup?: string;
    userId?: string;
    username?: string;
    ruleDesc?: string;
    riskCount?: 0;
    context?: string;
    advice?: string;
    link?: string;
    status?: 'valid' | 'invalid';
    ruleRego?: 'string';
    ruleGroupNameList?: Array<string>;
    ruleTypeList?: Array<string>;
    ruleTypeNameList?: Array<string>;
    linkedDataList?: Array<any>;
    linkedDataDesc?: string;
    globalVariableConfigIdList?: Array<any>;
    ruleCode?: string;
    tags?: Array<string>;
  }

  interface Result_RiskCard {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<BaseRiskCard>;
      total: number;
    };
  }

  interface IPolicy {
    policyName: string;
    policyType: string;
    source: string;
    lastUsed: string;
    riskLevel: string;
    policyDocument: string;
  }

  interface BaseIdentity {
    id?: number;
    page?: number;
    size?: number;
    cloudAccountId?: string;
    ruleIds?: string;
    tags?: Array<string>;
    cloudResourceId?: string;
    resourceName?: string;
    visitTypes?: Array<string>;
    unusedPermissions?: string;
    accessKeyIds?: string;
    accessInfos?: [
      {
        accessKeyId: string;
        visitTypes: Array<string>;
        tags: string;
      },
    ];
    userInfo?: {
      userName: string;
      platform: string;
      email: string;
      status: string;
      createDate: string;
      lastLoginDate: string;
      mfastatus: boolean;
    };
    policies?: Array<IPolicy>;
    activityLogs?: Array<any>;
    riskInfos?: Array<any>;
    platform?: string;
    resourceType?: string;
    resourceTypeGroup?: string;
  }

  interface Result_Identity {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: {
      data: Array<BaseIdentity>;
      total: number;
    };
  }

  interface Result_Identity_Detail {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: BaseIdentity;
  }

  interface BaseIdentityRisk {
    id?: number;
    ruleName?: string;
    ruleDesc?: string;
    context?: string;
  }

  interface Result_IdentityRisk {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<Base_Risk>;
  }

  interface BaseIdentityCard {
    platformList?: Array<string>;
    ruleId?: number;
    ruleCode?: string;
    platform?: string;
    ruleName?: string;
    riskLevel?: string;
    userCount?: number;
  }

  interface Result_IdentityCard {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<BaseIdentityCard>;
  }

  interface Result_GroupTag {
    code: number;
    errorCode: number;
    errorMsg: string;
    msg: string;
    content: Array<string>;
  }

  type CollectorRecord = {
    id: number;
    gmtCreate: string;
    gmtModified: string;
    platform: string;
    cloudAccountId: string;
    alias: string;
    startTime: string;
    endTime: string;
    percent: string;
    errorResourceTypeList: string[];
    collectorName: string;
  };

  type CollectorRecordListRequest = {
    cloudAccountId: string;
    platform: string;
    startTimeArray?: string[];
  };

  type CollectorRecordListResponse = {
    data: CollectorRecord[];
    total: number;
  };

  interface ListRuleRequest {
    page?: number;
    size?: number;
    ruleGroupIdList?: Array<number>;
    ruleName?: string;
    riskLevel?: string;
    riskLevelList?: Array<string>;
    platform?: string;
    platformList?: Array<string>;
    resourceType?: string;
    resourceTypeList?: Array<Array<string>>;
    ruleDesc?: string;
    groupName?: string;
    groupNameList?: Array<string>;
    ruleTypeIdList?: Array<Array<number>>;
    status?: string;
    sortParam?: string;
    sortType?: string;
    ruleCodeList?: Array<string>;
  }

  interface AddTenantSelectRuleRequest {
    /** 规则代码，规则的唯一标识 */
    ruleCode: string;
  }

  interface DeleteTenantSelectRuleRequest {
    /** 规则代码，规则的唯一标识 */
    ruleCode: string;
  }
}
