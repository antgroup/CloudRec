/*
 Navicat MySQL Dump SQL

 Source Server         : docke-mysql
 Source Server Type    : MySQL
 Source Server Version : 80040 (8.0.40)
 Source Host           : localhost:3306
 Source Schema         : cloudrec

 Target Server Type    : MySQL
 Target Server Version : 80040 (8.0.40)
 File Encoding         : 65001

 Date: 09/01/2025 15:06:17
*/

CREATE database if NOT EXISTS `cloudrec_db` default character set utf8mb4 collate utf8mb4_unicode_ci;
USE `cloudrec_db`;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = agent_registry   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `agent_registry` (
                                                `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台标识',
    `registry_value` varchar(255) DEFAULT NULL COMMENT '执行信息',
    `registry_time` timestamp NULL DEFAULT NULL COMMENT '最新一次注册时间',
    `cloud_account_id` mediumtext DEFAULT NULL COMMENT '执行的账号列表',
    `cron` varchar(255) DEFAULT NULL COMMENT 'cron',
    `status` varchar(255) DEFAULT NULL COMMENT '健康状态',
    `agent_name` varchar(255) DEFAULT NULL COMMENT '自定义agent name',
    `secret_key` varchar(255) DEFAULT NULL COMMENT '对称加密的key',
    `persistent_token` varchar(255) DEFAULT NULL COMMENT '持久化的token',
    `once_token` varchar(255) DEFAULT NULL COMMENT '使用的一次性token',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'agent执行信息';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = agent_registry_cloud_account   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `agent_registry_cloud_account` (
                                                              `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `registry_value` varchar(255) DEFAULT NULL COMMENT 'agent地址',
    `agent_registry_id` bigint(20) unsigned DEFAULT NULL COMMENT '关联agent表id',
    `cloud_account_id` varchar(255) DEFAULT NULL COMMENT '云账号id',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_agent_id_cloud_account_id_platform`(`agent_registry_id`, `cloud_account_id`, `platform`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'agent运行的账号信息';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = agent_registry_token   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `agent_registry_token` (
                                                      `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `once_token` varchar(255) DEFAULT NULL COMMENT '临时token',
    `used` int(11) unsigned DEFAULT NULL COMMENT '临时token是否使用',
    `once_token_create_time` timestamp NULL DEFAULT NULL COMMENT '临时token的创建时间',
    `agent_registry_id` bigint(20) unsigned DEFAULT NULL COMMENT '关联的注册agent的id',
    `user_id` varchar(255) DEFAULT NULL COMMENT '注册token创建人的user_id',
    `once_token_expire_time` timestamp NULL DEFAULT NULL COMMENT '临时token的过期时间',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'agent 注册用的token';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = cloud_account   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `cloud_account` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '云账号id',
    `cloud_id` varchar(255) DEFAULT NULL COMMENT '云id',
    `ak` varchar(255) DEFAULT NULL COMMENT 'ak',
    `sk` varchar(255) DEFAULT NULL COMMENT 'sk',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `status` varchar(255) DEFAULT NULL COMMENT 'ak sk 状态',
    `user_id` varchar(255) DEFAULT NULL COMMENT '账号录入人id',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '云账号归属租户',
    `last_scan_time` timestamp NULL DEFAULT NULL COMMENT '最近一次扫描时间',
    `resource_type_list` varchar(2048) DEFAULT NULL COMMENT '对接云服务',
    `collector_status` varchar(255) DEFAULT NULL COMMENT '采集状态：运行中、等待运行',
    `alias` varchar(255) DEFAULT NULL COMMENT '云账号别名',
    `account_status` varchar(255) DEFAULT NULL COMMENT '账号状态',
    `credentials_json` mediumtext DEFAULT NULL COMMENT 'gcp认证json',
    `site` varchar(255) DEFAULT NULL COMMENT '部署站点标识',
    `owner` varchar(255) DEFAULT NULL COMMENT '账号负责人',
    PRIMARY KEY(`id`),
    KEY `idx_cloud_account_id_platform`(`cloud_account_id`, `platform`),
    KEY `idx_last_scan_time_tenant_id`(`last_scan_time`, `tenant_id`),
    KEY `idx_tenant_id`(`tenant_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '云账号';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = cloud_ram   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `cloud_ram` (
                                           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id',
    `user_type` varchar(255) DEFAULT NULL COMMENT '账号类型：主账号、子账号',
    `detail` mediumtext DEFAULT NULL COMMENT '完整信息json',
    `ak_num` int(11) unsigned DEFAULT '0' COMMENT 'ak 数量',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '主账号id',
    `alias` varchar(255) DEFAULT NULL COMMENT '主账号别名',
    `acl_status` varchar(255) DEFAULT NULL COMMENT '访问控制状态',
    `platform` varchar(255) NOT NULL COMMENT '云平台',
    `user_name` varchar(512) DEFAULT NULL COMMENT '用户名称',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_user_id_cloud_account_id_platform`(`user_id`, `cloud_account_id`, `platform`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '云上用户认证信息';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = cloud_resource_instance_v1   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `cloud_resource_instance_v1` (
                                                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(100) DEFAULT NULL COMMENT '平台',
    `cloud_account_id` varchar(100) DEFAULT NULL COMMENT '云账号id',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资产类型',
    `address` varchar(255) DEFAULT NULL COMMENT 'address',
    `instance` mediumtext DEFAULT NULL COMMENT '资产实例json',
    `resource_id` varchar(255) DEFAULT NULL COMMENT '资产id',
    `resource_name` varchar(255) DEFAULT NULL COMMENT '资产name',
    `version` varchar(255) DEFAULT NULL COMMENT 'version',
    `alias` varchar(255) DEFAULT NULL COMMENT '云账号别名',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `deleted_at` timestamp NULL DEFAULT NULL COMMENT '删除时间',
    `custom_field_value` mediumtext DEFAULT NULL COMMENT '自定义字段值',
    `region` varchar(255) DEFAULT NULL COMMENT 'region',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_resource_id_cloud_account_resouce_type_platform`(`resource_id`, `cloud_account_id`, `resource_type`, `platform`),
    KEY `idx_resource_type_platform_tenant_id`(`resource_type`, `platform`, `tenant_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '云资产数据';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = cloud_resource_risk_count_statistics   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `cloud_resource_risk_count_statistics` (
                                                                      `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资源类型',
    `total_risk_count` int(11) unsigned DEFAULT NULL COMMENT '风险总数',
    `high_level_risk_count` int(11) unsigned DEFAULT NULL COMMENT '高',
    `medium_level_risk_count` int(11) unsigned DEFAULT NULL COMMENT '中',
    `low_level_risk_count` int(11) unsigned DEFAULT NULL COMMENT '低',
    `update_time` timestamp NULL DEFAULT NULL COMMENT '数据更新时间',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `resource_count` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '资产数量',
    PRIMARY KEY(`id`),
    KEY `idx_platform_resource_type_update_time`(`platform`, `resource_type`, `update_time`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '资产风险数量统计';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = collector_log   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `collector_log` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `cloud_account_id` varchar(255) DEFAULT NULL COMMENT '云账号id',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资产信息',
    `type` varchar(255) NOT NULL COMMENT '异常类型',
    `message` mediumtext NOT NULL COMMENT '异常日志',
    `unique_key` varchar(512) NOT NULL COMMENT '唯一键',
    `description` varchar(512) DEFAULT NULL COMMENT '简单描述',
    `level` varchar(255) NOT NULL COMMENT '日志级别',
    `time` varchar(255) NOT NULL COMMENT '日志时间',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_unique_key`(`unique_key`),
    KEY `idx_cloud_account_id_resource_type_platform`(`cloud_account_id`, `resource_type`, `platform`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '采集器日志回流记录';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = daily_risk_management   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `daily_risk_management` (
                                                       `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `create_date` varchar(255) DEFAULT NULL COMMENT '创建时间',
    `handle_count` int(11) DEFAULT NULL COMMENT '已处理数量',
    `not_handle_count` int(11) DEFAULT NULL COMMENT '未处理数量',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_tenant_id_create_date`(`tenant_id`, `create_date`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '每日风险数据';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = db_cache   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `db_cache` (
                                          `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `cache_key` varchar(255) DEFAULT NULL COMMENT '缓存key',
    `cache_time` timestamp NULL DEFAULT NULL COMMENT '最近一次缓存时间',
    `value` mediumtext DEFAULT NULL COMMENT '缓存查询结果值',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_cache_key`(`cache_key`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '缓存数据';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName =_variable_config   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `global_variable_config` (
                                                        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `name` varchar(255) DEFAULT NULL COMMENT '全局变量名称',
    `path` varchar(255) DEFAULT NULL COMMENT '全局变量的唯一标识',
    `data` mediumtext DEFAULT NULL COMMENT '全局变量json数据，任意定义',
    `username` varchar(255) DEFAULT NULL COMMENT '创建人name',
    `user_id` varchar(255) DEFAULT NULL COMMENT '创建人id',
    `version` varchar(255) DEFAULT NULL COMMENT '版本',
    `status` varchar(255) DEFAULT NULL COMMENT '状态',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_path`(`path`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '全局变量配置';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = global_variable_config_rule_rel   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `global_variable_config_rule_rel` (
                                                                 `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则id',
    `global_variable_config_id` bigint(20) unsigned DEFAULT NULL COMMENT '全局变量的id',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_rule_id_v_id`(`rule_id`, `global_variable_config_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '全局变量和规则关联表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = history_data_everyday_statistics   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `history_data_everyday_statistics` (
                                                                  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform_count` int(11) unsigned DEFAULT '0' COMMENT '平台数量',
    `cloud_account_count` int(11) unsigned DEFAULT '0' COMMENT '云账号数',
    `risk_count` bigint(20) unsigned DEFAULT '0' COMMENT '风险数',
    `resource_count` bigint(20) unsigned DEFAULT '0' COMMENT '资产数',
    `create_date` varchar(255) DEFAULT NULL COMMENT '创建日期',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `detail_json` text DEFAULT NULL COMMENT '数据json',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '历史数据每日统计数据';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = identity_entity   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `identity_entity` (
                                                 `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `gmt_delete` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '删除时间',
    `entity_name` varchar(255) NOT NULL COMMENT '实体名称',
    `resource_id` varchar(512) NOT NULL COMMENT '与资源模块的ID一一对应',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '对应的巡检账号',
    `platform` varchar(255) NOT NULL COMMENT '云平台',
    `identity_type` varchar(255) NOT NULL COMMENT '身份类型',
    `auth_method` varchar(255) DEFAULT '' COMMENT '认证方式',
    `labels` varchar(512) DEFAULT NULL COMMENT '标签',
    `details` mediumtext DEFAULT NULL COMMENT '身份实体详情',
    `permissions` varchar(2048) DEFAULT NULL COMMENT '权限',
    `activity_histories` varchar(2048) DEFAULT NULL COMMENT '从EDR结果同步的历史活动',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '云身份实体表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = identity_entity_associate   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `identity_entity_associate` (
                                                           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `associated_entity_list` varchar(1) DEFAULT NULL COMMENT '关联身份实体列表',
    `associated_entity_number` int(11) DEFAULT NULL COMMENT '关联数量',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '身份实体关联关系表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = identity_security   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `identity_security` (
                                                   `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `tags` varchar(255) DEFAULT NULL COMMENT '资产标签',
    `access_type` varchar(255) DEFAULT NULL COMMENT '访问方式 API / Console',
    `access_infos` mediumtext DEFAULT NULL COMMENT '认证信息json',
    `user_info` mediumtext DEFAULT NULL COMMENT '账户信息json',
    `policies` mediumtext DEFAULT NULL COMMENT '策略信息json',
    `activity_logs` mediumtext DEFAULT NULL COMMENT '活动日志 保留字段',
    `instance` mediumtext DEFAULT NULL COMMENT '资产实例json',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `cloud_account_id` varchar(255) DEFAULT NULL COMMENT '云账号id',
    `rule_ids` varchar(1024) DEFAULT NULL COMMENT '规则id',
    `resource_id` varchar(255) DEFAULT NULL COMMENT '云资产数据id',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '云资产类型',
    `resource_type_group` varchar(255) DEFAULT NULL COMMENT '云平台资产类型 User / Service Account',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '身份模块数据';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = local_task_execute_log   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `local_task_execute_log` (
                                                        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `task_name` varchar(100) NOT NULL COMMENT '定时任务名',
    `execute_host` varchar(100) DEFAULT NULL COMMENT '定时任务名',
    `result` varchar(100) DEFAULT NULL COMMENT '执行结果',
    `msg` text DEFAULT NULL COMMENT '执行结果',
    `start_time` timestamp NULL DEFAULT NULL COMMENT '开始时间',
    `end_time` timestamp NULL DEFAULT NULL COMMENT '结束时间',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '本地定时任务记录表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = local_task_locks   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `local_task_locks` (
                                                  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `task_name` varchar(100) NOT NULL COMMENT '定时任务名',
    `execute_host` varchar(100) DEFAULT NULL COMMENT '执行机器',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_task_name`(`task_name`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '本地定时任务调度表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = lunar_lock   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `lunar_lock` (
                                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `lock_name` varchar(255) NOT NULL COMMENT '锁名称',
    `value` varchar(1024) DEFAULT NULL COMMENT '值',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_lock_name`(`lock_name`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '锁表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = message   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `message` (
                                         `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id',
    `message` mediumtext DEFAULT NULL COMMENT '信息',
    `status` varchar(255) DEFAULT NULL COMMENT '状态已读、未读',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '站内信息';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = open_api_auth   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `open_api_auth` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `user_id` varchar(255) DEFAULT NULL COMMENT 'userid',
    `access_key` varchar(255) DEFAULT NULL COMMENT 'access key',
    `secret_key` varchar(255) DEFAULT NULL COMMENT 'secret key',
    `remark` varchar(1024) DEFAULT NULL COMMENT '备注信息',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'open api 认证信息';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = operation_log   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `operation_log` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id',
    `action` varchar(255) DEFAULT NULL COMMENT '动作',
    `notes` mediumtext DEFAULT NULL COMMENT '备注',
    `type` varchar(255) DEFAULT NULL COMMENT '日志类型',
    `correlation_id` bigint(20) DEFAULT NULL COMMENT '关联数据id，扫描结果、规则、或者人员',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '操作日志';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = platform   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `platform` (
                                          `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台英文表示',
    `platform_name` varchar(255) DEFAULT NULL COMMENT '平台中文标识',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_platform`(`platform`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '平台表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = resource   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `resource` (
                                          `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资源类型',
    `resource_name` varchar(255) DEFAULT NULL COMMENT '资源名称',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台标识',
    `resource_group_type` varchar(255) DEFAULT NULL COMMENT '资源所属的资源组类型',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_platform_resource_type`(`platform`, `resource_type`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '资源类型枚举表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = resource_detail_config   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `resource_detail_config` (
                                                        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资产类型',
    `path` varchar(255) DEFAULT NULL COMMENT '用户自定义解析字段路径',
    `name` varchar(255) DEFAULT NULL COMMENT '用户自定义解析字段名称',
    `user` varchar(255) DEFAULT NULL COMMENT '配置人',
    `status` varchar(255) DEFAULT NULL COMMENT '启用与禁用状态',
    `type` varchar(255) DEFAULT NULL COMMENT '类型',
    `modified` int(11) unsigned DEFAULT NULL COMMENT '是否被修改',
    PRIMARY KEY(`id`),
    KEY `idx_platform_resource_type`(`platform`, `resource_type`, `type`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '资产详情页配置';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = role   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `role` (
                                      `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `role_name` varchar(255) DEFAULT NULL COMMENT '角色名称',
    `role_desc` varchar(512) DEFAULT NULL COMMENT '角色描述',
    `status` varchar(255) DEFAULT NULL COMMENT '状态',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '角色表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule` (
                                      `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_group_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则组id',
    `rule_name` varchar(255) DEFAULT NULL COMMENT '规则名称',
    `rule_desc` text DEFAULT NULL COMMENT '规则描述',
    `risk_level` varchar(255) DEFAULT NULL COMMENT '风险等级',
    `platform` varchar(255) DEFAULT NULL COMMENT '云平台',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资源类型',
    `rule_rego_id` bigint(20) unsigned DEFAULT NULL COMMENT '关联的rego 规则id',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id（预留字段）',
    `last_scan_time` timestamp NULL DEFAULT NULL COMMENT '最近一次扫描结束时间',
    `status` varchar(255) DEFAULT NULL COMMENT '状态',
    `context` mediumtext DEFAULT NULL COMMENT '上下文',
    `advice` text DEFAULT NULL COMMENT '建议',
    `link` text DEFAULT NULL COMMENT '操作文档',
    `linked_data_list` text DEFAULT NULL COMMENT '关联数据的json',
    `rule_code` varchar(255) DEFAULT NULL COMMENT '规则code',
    `risk_count` int(11) unsigned DEFAULT '0' COMMENT '规则扫描出的风险数',
    `is_running` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '是否运行',
    `last_scan_time_start` timestamp NULL DEFAULT NULL COMMENT '最近一次扫描开始时间',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_code`(`rule_code`),
    KEY `idx_platform_resource_type`(`platform`, `resource_type`),
    KEY `idx_status`(`status`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '检测规则';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_group   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_group` (
                                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `group_name` varchar(255) DEFAULT NULL COMMENT '规则组名称',
    `group_desc` varchar(2048) DEFAULT NULL COMMENT '规则组描述',
    `username` varchar(255) DEFAULT NULL COMMENT '创建人',
    `last_scan_start_time` timestamp NULL DEFAULT NULL COMMENT '最近一次扫描开始时间',
    `last_scan_end_time` timestamp NULL DEFAULT NULL COMMENT '最近一次扫描结束时间',
    `high_level_risk_count` bigint(20) DEFAULT NULL COMMENT '高风险数',
    `medium_level_risk_count` bigint(20) DEFAULT NULL COMMENT '中风险数',
    `low_level_risk_count` bigint(20) DEFAULT NULL COMMENT '低风险数',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '规则组';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_group_rel   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_group_rel` (
                                                `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则id',
    `rule_group_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则组id',
    `rule_code` varchar(255) DEFAULT NULL COMMENT '规则code',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_rule_id_group_id`(`rule_id`, `rule_group_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '规则规则组关联';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_rego   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_rego` (
                                           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_rego` mediumtext DEFAULT NULL COMMENT 'rego规则',
    `is_draft` int(11) DEFAULT NULL COMMENT '是否草稿',
    `version` int(11) DEFAULT NULL COMMENT '版本号',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资源类型',
    `rule_id` bigint(20) unsigned DEFAULT NULL COMMENT '关联的规则id',
    `rego_package` varchar(255) DEFAULT NULL COMMENT 'rego规则包路径',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'rego规则';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_scan_result   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_scan_result` (
                                                  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_id` bigint(20) unsigned NOT NULL COMMENT '规则id',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '云账号id',
    `resource_id` varchar(255) NOT NULL COMMENT '资源id',
    `resource_name` varchar(255) DEFAULT NULL COMMENT '资源名称',
    `update_time` varchar(255) DEFAULT NULL COMMENT '资源更新时间',
    `platform` varchar(255) DEFAULT NULL COMMENT '平台',
    `resource_type` varchar(255) DEFAULT NULL COMMENT '资源类型',
    `result` mediumtext NOT NULL COMMENT '检测结果',
    `region` varchar(255) DEFAULT NULL COMMENT '区域信息',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `status` varchar(255) DEFAULT NULL COMMENT '风险状态',
    `rule_snapshoot` mediumtext DEFAULT NULL COMMENT '规则快照',
    `resource_snapshoot` mediumtext DEFAULT NULL COMMENT '资产数据快照',
    `ignore_reason_type` varchar(255) DEFAULT NULL COMMENT '忽略风险：忽略原因类型',
    `ignore_reason` varchar(1024) DEFAULT NULL COMMENT '忽略的原因',
    `version` bigint(20) unsigned DEFAULT '0' COMMENT '数据版 version',
    `is_new` int(11) DEFAULT NULL COMMENT '是否是新风险',
    `cloud_resource_instance_id` bigint(20) unsigned DEFAULT NULL COMMENT '关联资产表id',
    `resource_status` varchar(255) DEFAULT NULL COMMENT '资产状态',
    `whited_id` bigint(20) unsigned DEFAULT NULL COMMENT '白名单id',
    PRIMARY KEY(`id`),
    KEY `idx_cloud_account_id_rule_id`(`cloud_account_id`, `rule_id`),
    KEY `idx_rule_id`(`rule_id`),
    KEY `idx_platfrom_resource_type_status`(`platform`, `resource_type`, `status`),
    KEY `idx_status_tenant_id_platform_resource_type`(`status`, `tenant_id`, `platform`, `resource_type`),
    KEY `idx_resource_id_resource_name`(`resource_id`, `resource_name`),
    KEY `idx_rule_id_status_tenant_id_platform`(`rule_id`, `status`, `tenant_id`, `platform`),
    KEY `idx_cloud_resource_instance_id`(`cloud_resource_instance_id`),
    KEY `idx_resource_id_rule_id_status`(`resource_id`, `rule_id`, `status`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '规则扫描风险结果';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_scan_risk_count_statistics   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_scan_risk_count_statistics` (
                                                                 `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_id` bigint(20) unsigned NOT NULL COMMENT '规则id',
    `count` int(11) NOT NULL DEFAULT '0' COMMENT '风险数量',
    `tenant_id` bigint(20) unsigned NOT NULL COMMENT '租户id',
    `update_time` timestamp NOT NULL COMMENT '更新时间',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_rule_id_tenant_id_update_time`(`rule_id`, `tenant_id`, `update_time`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '规则扫描风险数量统计';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_type   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_type` (
                                           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `type_name` varchar(255) DEFAULT NULL COMMENT '类型名称',
    `parent_id` bigint(20) unsigned DEFAULT NULL COMMENT '父级类目',
    `status` varchar(255) DEFAULT NULL COMMENT 'status',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = 'rule_type';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = rule_type_rel   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `rule_type_rel` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则id',
    `rule_type_id` bigint(20) unsigned DEFAULT NULL COMMENT '规则类型id',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_rule_type_rule_id`(`rule_id`, `rule_type_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '规则与类型关系';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = running_progress   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `running_progress` (
                                                  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `total` int(11) unsigned DEFAULT '0' COMMENT '总任务',
    `finished_count` int(11) unsigned DEFAULT '0' COMMENT '当前完成的任务数',
    `result` mediumtext DEFAULT NULL COMMENT '运行结果',
    `status` varchar(255) DEFAULT NULL COMMENT '任务状态',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '运行进度';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = secret_key   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `secret_key` (
                                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `secret_key_name` varchar(255) DEFAULT NULL COMMENT 'secret_key_name',
    `secret_key_value` varchar(255) DEFAULT NULL COMMENT 'secret_key_value',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_secret_key_name`(`secret_key_name`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '加密信息表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = security_product_posture   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `security_product_posture` (
                                                          `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) NOT NULL COMMENT '平台',
    `tenant_id` bigint(20) unsigned NOT NULL COMMENT '云账号租户id',
    `resource_type` varchar(255) NOT NULL COMMENT '资源类型',
    `resource_id` varchar(512) DEFAULT NULL COMMENT '资源id',
    `resource_name` varchar(512) DEFAULT NULL COMMENT '资源名称',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '云账号id',
    `product_type` varchar(255) NOT NULL COMMENT '云产品类型（防止resourceType变更）',
    `status` varchar(255) NOT NULL COMMENT '开通状态',
    `policy` mediumtext DEFAULT NULL COMMENT '开通策略',
    `policy_detail` mediumtext DEFAULT NULL COMMENT '策略详情',
    `version` varchar(255) DEFAULT NULL COMMENT '版本',
    `version_desc` varchar(255) DEFAULT NULL COMMENT '版本的描述信息',
    `protected_count` int(11) unsigned DEFAULT NULL COMMENT '防护数量',
    `total` int(11) unsigned DEFAULT NULL COMMENT '应该防护的数量',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_cloud_account_id_type`(`cloud_account_id`, `product_type`, `resource_type`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '安全产品态势';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = subscription   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `subscription` (
                                              `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `name` varchar(255) DEFAULT NULL COMMENT '订阅名称',
    `action` varchar(255) DEFAULT NULL COMMENT '订阅动作',
    `rule_config` text DEFAULT NULL COMMENT '订阅的条件json',
    `condition` varchar(255) DEFAULT NULL COMMENT '条件关系',
    `rule_config_json` mediumtext DEFAULT NULL COMMENT '加工后的规则',
    `ding_url` varchar(1024) DEFAULT NULL COMMENT '钉钉群告警url（废弃）',
    `ding_name` varchar(255) DEFAULT NULL COMMENT '钉钉群名称（废弃）',
    `time` varchar(255) DEFAULT NULL COMMENT '通知时间（废弃）',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `user_id` varchar(255) DEFAULT NULL COMMENT '配置人',
    `action_list` mediumtext DEFAULT NULL COMMENT '订阅动作配置',
    `status` varchar(255) DEFAULT NULL COMMENT '状态：有效、无效',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '订阅记录';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = subscription_action   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `subscription_action` (
                                                     `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `action_type` varchar(255) NOT NULL COMMENT '类型：定时和实时',
    `action` varchar(255) DEFAULT NULL COMMENT '钉钉群、企业微信、接口会调',
    `name` varchar(255) DEFAULT NULL COMMENT '名称',
    `url` varchar(1024) DEFAULT NULL COMMENT '地址',
    `period` varchar(255) DEFAULT NULL COMMENT 'period',
    `time_list` varchar(255) DEFAULT NULL COMMENT '告警时间',
    `subscription_id` bigint(20) unsigned NOT NULL COMMENT '订阅id',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '订阅活动配置';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = system_config   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `system_config` (
                                               `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `config_type` varchar(128) NOT NULL COMMENT '配置类',
    `config_key` varchar(128) NOT NULL COMMENT '配置key',
    `config_value` text NOT NULL COMMENT '配置值',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_config`(`config_type`, `config_key`),
    KEY `idx_config_type`(`config_type`),
    KEY `idx_config_key`(`config_key`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '系统配置项';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = tenant   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `tenant` (
                                        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `tenant_name` varchar(255) DEFAULT NULL COMMENT '租户名称',
    `tenant_desc` text DEFAULT NULL COMMENT '描述',
    `status` varchar(255) DEFAULT NULL COMMENT '状态信息',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '租户表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = tenant_user   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `tenant_user` (
                                             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户表id',
    `user_id` bigint(20) unsigned DEFAULT NULL COMMENT '用户表id',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_user_id_tenant_id`(`tenant_id`, `user_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '租户与用户关联表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = user   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `user` (
                                      `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `username` varchar(255) DEFAULT '' COMMENT '用户名称',
    `user_id` varchar(255) NOT NULL COMMENT '用户id',
    `status` varchar(255) DEFAULT NULL COMMENT '账号状态',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户表id，当前选择的租户id',
    `role_name` varchar(255) DEFAULT NULL COMMENT '角色名称',
    `password` varchar(255) DEFAULT NULL COMMENT '密码',
    `last_login_time` timestamp NULL DEFAULT NULL COMMENT '最近登录时间',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_user_id`(`user_id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '用户表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = user_log   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `user_log` (
                                          `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `content` text DEFAULT NULL COMMENT '信息',
    `user_id` varchar(255) DEFAULT NULL COMMENT '用户id',
    `username` varchar(255) DEFAULT NULL COMMENT 'username',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '用户操作日志';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = user_role   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `user_role` (
                                           `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `user_id` bigint(20) unsigned DEFAULT NULL COMMENT '用户表主键',
    `role_id` bigint(20) unsigned DEFAULT NULL COMMENT '角色表id',
    PRIMARY KEY(`id`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '用户角色关联表';

/********************************************************************/
/*   DatabaseName = cloudrec_db   */
/*   TableName = whited_rule_config   */
/********************************************************************/
CREATE TABLE IF NOT EXISTS `whited_rule_config` (
                                                    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `rule_type` varchar(255) NOT NULL COMMENT '规则类型：RULE_ENGINE(规则引擎)，REGO（rego）',
    `rule_name` varchar(255) NOT NULL COMMENT '规则名称',
    `rule_desc` varchar(255) DEFAULT NULL COMMENT '规则描述',
    `rule_config` text DEFAULT NULL COMMENT '规则条件json',
    `condition` varchar(255) DEFAULT NULL COMMENT '条件关系描述',
    `rule_config_json` mediumtext DEFAULT NULL COMMENT '加工后的规则',
    `rego_content` mediumtext DEFAULT NULL COMMENT 'rego规则内容',
    `tenant_id` bigint(20) unsigned DEFAULT NULL COMMENT '租户id',
    `creator` varchar(128) NOT NULL COMMENT '创建人',
    `lock_holder` varchar(128) DEFAULT NULL COMMENT '持锁人',
    `enable` tinyint(3) unsigned DEFAULT '0' COMMENT '是否生效 0无效 1生效',
    `risk_rule_code` varchar(128) DEFAULT NULL COMMENT '风险检测规则code',
    PRIMARY KEY(`id`),
    UNIQUE KEY `uk_ruletype_rulename`(`rule_type`, `rule_name`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COMMENT = '白名单规则配置';

CREATE TABLE IF NOT EXISTS `collector_task` (
                                                `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `type` varchar(100) DEFAULT NULL COMMENT '任务类型',
    `param` text DEFAULT NULL COMMENT '任务参数',
    `cloud_account_id` varchar(255) DEFAULT NULL COMMENT '云账号ID',
    `platform` varchar(255) DEFAULT NULL COMMENT '云平台',
    `user_id` varchar(255) DEFAULT NULL COMMENT 'user_id',
    `status` varchar(100) DEFAULT NULL COMMENT '状态',
    `registry_value` varchar(255) DEFAULT NULL COMMENT '采集器唯一id',
    `lock_time` timestamp NULL DEFAULT NULL COMMENT '锁定时间',
    PRIMARY KEY(`id`),
    KEY `idx_platform_status`(`platform`, `status`) ,
    KEY `idx_account_status`(`cloud_account_id`, `status`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4  COMMENT = '采集器任务';

CREATE TABLE IF NOT EXISTS `collector_record` (
                                                  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
    `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    `platform` varchar(255) NOT NULL COMMENT '云平台',
    `cloud_account_id` varchar(255) NOT NULL COMMENT '账号id',
    `start_time` timestamp NOT NULL COMMENT '开始时间',
    `end_time` timestamp NULL DEFAULT NULL COMMENT '结束时间',
    `registry_value` varchar(255) DEFAULT NULL COMMENT '采集器注册的唯一key',
    PRIMARY KEY(`id`),
    KEY `idx_platform_account_time`(`platform`, `cloud_account_id`, `start_time`)
    ) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4  COMMENT = '采集记录';

ALTER TABLE `collector_log`
    ADD COLUMN `collector_record_id` bigint(20) unsigned DEFAULT NULL COMMENT '采集记录id';

ALTER TABLE `collector_log`
    ADD KEY `idx_record_id_desp`(`collector_record_id`, `description`(255), `cloud_account_id`) ;

ALTER TABLE `cloud_resource_instance_v1`
    ADD COLUMN `del_num` int(11) unsigned DEFAULT '0' COMMENT '删除次数';

ALTER TABLE `agent_registry`
    ADD COLUMN `health_status` varchar(512) DEFAULT NULL COMMENT '服务运行信息';

ALTER TABLE `cloud_account`
    ADD COLUMN `proxy_config` text DEFAULT NULL COMMENT '代理信息';

ALTER TABLE `cloud_account`
    ADD COLUMN `email` varchar(255) DEFAULT NULL COMMENT '邮箱';

CREATE TABLE `tenant_rule` (
   `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
   `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
   `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
   `tenant_id` bigint(20) unsigned NOT NULL COMMENT '租户id',
   `rule_code` varchar(255) NOT NULL COMMENT '规则code',
   PRIMARY KEY(`id`)
) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4  COMMENT = '租户自选规则';

ALTER TABLE `tenant_user`
    ADD COLUMN `role_name` varchar(100) NOT NULL DEFAULT 'user' COMMENT '用户角色，user、admin';


CREATE TABLE `invite_code` (
   `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '主键',
   `gmt_create` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
   `gmt_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
   `inviter` varchar(255) NOT NULL COMMENT '邀请人ID',
   `code` varchar(512) NOT NULL COMMENT '邀请码',
   `user_id` varchar(255) DEFAULT NULL COMMENT '受邀人ID，若ID为null代表邀请码未使用',
   `tenant_id` bigint(20) NOT NULL COMMENT '初始化的租户ID',
   PRIMARY KEY(`id`),
   UNIQUE KEY `uk_code`(`code`)
) AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4  COMMENT = '邀请码';


ALTER TABLE `collector_record`
    ADD COLUMN `collect_record_info` mediumtext DEFAULT NULL COMMENT '采集记录信息 JSON';

ALTER TABLE `cloud_account` ADD COLUMN `enable_inverse_selection` tinyint(4) DEFAULT '0' COMMENT '资产类型是否反选0,1';
