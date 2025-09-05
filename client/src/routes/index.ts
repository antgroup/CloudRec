const routes = [
  {
    path: '/',
    redirect: '/home',
  },
  {
    title: 'layout.routes.title.home',
    path: '/home',
    icon: 'PieChartOutlined',
    component: '@/pages/Home',
  },
  {
    title: 'layout.routes.title.cloudAccount',
    path: '/cloudAccount',
    icon: 'CloudServerOutlined',
    routes: [
      {
        path: '/cloudAccount',
        redirect: '/cloudAccount/accountList',
      },
      {
        path: '/cloudAccount/accountList',
        component: '@/pages/CloudAccount',
      },
      {
        title: 'cloudAccount.title.collection.record',
        path: '/cloudAccount/collectionRecord',
        component: '@/pages/CloudAccount/CollectionRecord',
        hideInMenu: true,
      },
      {
        title: 'cloudAccount.title.collection.record.detail',
        path: '/cloudAccount/collectionRecord/:id',
        component: '@/pages/CloudAccount/CollectionRecord/Detail',
        hideInMenu: true,
      },
    ],
  },
  {
    title: 'layout.routes.title.assetManagement',
    path: '/assetManagement',
    icon: 'ProductOutlined',
    routes: [
      {
        path: '/assetManagement',
        redirect: '/assetManagement/polymerize',
      },
      {
        title: 'layout.routes.title.assetPolymerize',
        path: '/assetManagement/polymerize',
        component: '@/pages/AssetManagement/polymerize',
      },
      {
        title: 'layout.routes.title.assetInformation',
        path: '/assetManagement/assetList',
        component: '@/pages/AssetManagement',
      },
      {
        title: 'layout.routes.title.assetAllocation',
        hideInMenu: true,
        path: '/assetManagement/asseConfig',
        component: '@/pages/AssetManagement/components/ConfigAsset.tsx',
      },
      {
        title: 'layout.routes.title.identityInformation',
        path: '/assetManagement/identityList',
        component: '@/pages/AssetManagement/Identity',
      },
      {
        title: 'layout.routes.title.identityAssociate',
        hideInMenu: true,
        path: '/assetManagement/identityAssociate',
        component: '@/pages/AssetManagement/module/IdentityAssociate.tsx',
      },
    ],
  },
  {
    title: 'layout.routes.title.ruleManagement',
    path: '/ruleManagement',
    icon: 'DeliveredProcedure',
    routes: [
      {
        path: '/ruleManagement',
        redirect: '/ruleManagement/ruleGroup',
      },
      {
        title: 'layout.routes.title.detectRuleGroup',
        path: '/ruleManagement/ruleGroup',
        component: '@/pages/RuleManagement/RuleGroup',
      },
      {
        title: 'layout.routes.title.detectRule',
        path: '/ruleManagement/ruleProject',
        hideChildrenInMenu: true,
        routes: [
          {
            path: '/ruleManagement/ruleProject',
            component: '@/pages/RuleManagement/RuleProject',
          },
          {
            title: 'layout.routes.title.editRuleDetails',
            path: '/ruleManagement/ruleProject/detail',
            component: '@/pages/RuleManagement/RuleProject/Detail',
          },
          {
            title: 'layout.routes.title.editRule',
            path: '/ruleManagement/ruleProject/edit',
            component:
              '@/pages/RuleManagement/RuleProject/components/EditPage.tsx',
          },
        ],
      },
      {
        title: 'layout.routes.title.whiteListManagement',
        path: '/ruleManagement/whiteList',
        component: '@/pages/RuleManagement/WhiteList',
      },
    ],
  },
  {
    title: 'layout.routes.title.riskManagement',
    path: '/riskManagement',
    icon: 'ScanOutlined',
    hideChildrenInMenu: true,
    routes: [
      {
        path: '/riskManagement',
        redirect: '/riskManagement/riskList',
      },
      {
        title: 'layout.routes.title.riskList',
        path: '/riskManagement/riskList',
        component: '@/pages/RiskManagement',
      },
      {
        title: 'layout.routes.title.riskDetail',
        path: '/riskManagement/riskDetail',
        component: '@/pages/RiskManagement/RiskDetail',
      },
    ],
  },
  {
    title: 'layout.routes.title.securityControl',
    path: '/securityManagement',
    icon: 'CarryOutOutlined',
    hideChildrenInMenu: true,
    routes: [
      {
        path: '/securityManagement',
        redirect: '/securityManagement/securityList',
      },
      {
        title: 'layout.routes.title.securityControl',
        path: '/securityManagement/securityList',
        component: '@/pages/SecurityControl',
      },
    ],
  },
  {
    title: 'layout.routes.title.operationsCenter',
    path: '/pivotManagement',
    icon: 'DesktopOutlined',
    routes: [
      {
        path: '/pivotManagement',
        redirect: '/pivotManagement/userModule',
      },
      {
        title: 'layout.routes.title.userManagement',
        path: '/pivotManagement/UserModule',
        component: '@/pages/PivotManagement/UserModule',
      },
      {
        title: 'layout.routes.title.tenantManagement',
        path: '/pivotManagement/TenantModule',
        hideChildrenInMenu: true,
        routes: [
          {
            path: '/pivotManagement/TenantModule',
            component: '@/pages/PivotManagement/TenantModule',
          },
        ],
      },
      {
        name: 'Collector',
        path: '/pivotManagement/AgentModule',
        component: '@/pages/PivotManagement/AgentModule',
      },
      {
        title: 'layout.routes.title.subscribeManagement',
        path: '/pivotManagement/InvolveModule',
        component: '@/pages/PivotManagement/InvolveModule',
      },
      {
        title: 'layout.routes.title.variableManagement',
        path: '/pivotManagement/VariableModule',
        component: '@/pages/PivotManagement/VariableModule',
      },
    ],
  },
  {
    title: 'layout.routes.title.userLogin',
    path: '/login',
    component: '@/pages/Login',
    hideInMenu: true,
    menuRender: false,
  },
  {
    title: 'layout.routes.title.invitation',
    path: '/invitation',
    component: '@/pages/Invitation',
    hideInMenu: true,
    menuRender: false,
  },
  {
    title: 'layout.routes.title.personalCenter',
    path: '/individual',
    component: '@/pages/Allocation/Individual',
    hideInMenu: true,
  },
  {
    path: '*',
    redirect: '/home',
  },
];
export default routes;
