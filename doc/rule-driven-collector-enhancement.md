# 规则驱动的资源采集增强流程

## 1. 目标
建立统一执行规范：
- 规则必须基于 `collector` 实际返回的 struct 字段编写
- 规则所需字段缺失时，必须先增强采集能力，再交付规则
- 保证规则可执行、可解释、可持续扩展

## 2. 适用范围
- 平台：当前以 AWS 为先，后续扩展至 ALI_CLOUD/GCP 等
- 目录：`collector/*` 与 `rules/*`
- 类型：NetworkExposure / IdentityAccess 等 CSPM 基线类规则

## 3. 核心原则
1. Struct-First
- 先阅读采集代码中的 struct（例如 `UserDetail`、`RoleDetail`、`InstanceDetail`）
- 规则输入字段只能使用 struct 中真实存在字段

2. Gap-Driven
- 规则需要但 struct 没有的字段，先做采集增强
- 禁止为了让规则通过而在规则中假设不存在字段

3. Contract-Frozen
- `metadata.resourceType` 必须与采集资源常量一致
- 已发布字段/命名不做破坏性重命名，仅增量扩展

## 4. 标准执行流程

### Step 1: 定义规则需求
- 明确风险场景、检测条件、风险等级
- 列出规则必需字段（字段路径 + 含义）

### Step 2: 对齐采集 struct
- 在 `collector/<platform>/collector/**` 中定位对应资源 struct
- 输出字段映射表：`规则字段 -> struct字段`

### Step 3: 缺口判断
- 若字段齐备：进入 Step 5
- 若字段缺失：进入 Step 4

### Step 4: 采集增强（先做）
- 在对应资源采集逻辑中补齐字段
- 必要时补充分页、错误处理、空值兼容
- 本地编译/单测通过后再进入规则开发

### Step 5: 规则实现
- 新建规则目录并交付 4 文件：
  - `policy.rego`
  - `metadata.json`
  - `relation.json`
  - `input.json`
- `policy.rego` 输出 `risk`，并包含可读 `messages`

### Step 6: 验证
- `opa eval` 最小回放通过
- 样例输入覆盖风险触发分支
- 若可行，增加“不触发”样例用于反例校验

### Step 7: 评审与合入
- 评审项：字段对齐、误报/漏报风险、命名规范、可维护性
- 通过后合入并更新规则清单

## 5. 字段对齐检查清单
- [ ] 已定位目标资源 struct
- [ ] 规则字段全部来自 struct
- [ ] 字段路径、类型、语义一致
- [ ] 缺口字段已通过采集增强补齐
- [ ] `resourceType` 与采集常量一致

## 6. 规则交付检查清单
- [ ] 规则目录 4 文件齐全
- [ ] `metadata` 必填字段完整
- [ ] `code` 全局唯一
- [ ] `policy` 可解析且输出 `risk`
- [ ] `relation` 可解析
- [ ] `input` 可回放

## 7. 采集增强检查清单
- [ ] 新增字段已进入资源输出 struct
- [ ] API 调用具备分页处理
- [ ] 错误不阻断同资源后续采集
- [ ] 编译通过（必要时模块内 `go test`）

## 8. 验收标准
- 规则与 struct 对齐率：100%
- 规则最小回放通过率：100%
- 规则依赖字段缺失率：0
- 采集增强后无编译错误

## 9. 典型案例（AWS）
- ELBv2 规则依赖监听器信息
- 原采集结构缺少 `Listeners`
- 先在 `ELBDetail` 中新增 `Listeners` 并补充 `DescribeListeners` 分页拉取
- 再编写/调整规则消费 `input.Listeners`

## 10. 反模式（禁止）
- 在规则中引用采集 struct 不存在字段
- 用样例输入伪造字段掩盖采集缺口
- `metadata.resourceType` 与采集常量不一致
- 未做回放验证直接提交规则
