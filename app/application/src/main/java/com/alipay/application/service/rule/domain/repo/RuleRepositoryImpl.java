/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.application.service.rule.domain.repo;


import com.alibaba.fastjson.JSON;
import com.alipay.application.service.rule.domain.GlobalVariable;
import com.alipay.application.service.rule.domain.RuleAgg;
import com.alipay.application.service.rule.domain.RuleGroup;
import com.alipay.application.service.rule.domain.repo.factory.MetadataParser;
import com.alipay.application.service.rule.domain.repo.factory.RuleFactory;
import com.alipay.application.service.rule.utils.DirectoryWalkerUtil;
import com.alipay.application.service.rule.utils.GitHubSyncUtil;
import com.alipay.application.service.system.domain.enums.Status;
import com.alipay.common.utils.Util;
import com.alipay.dao.dto.RuleDTO;
import com.alipay.dao.dto.RuleGroupDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

/*
 *@title RuleRepositoryImpl
 *@description
 *@author jietian
 *@version 1.0
 *@create 2025/3/12 10:45
 */
@Slf4j
@Repository
public class RuleRepositoryImpl implements RuleRepository {

    @Resource
    private RuleMapper ruleMapper;

    @Resource
    private RuleRegoMapper ruleRegoMapper;

    @Resource
    private RuleTypeRelMapper ruleTypeRelMapper;

    @Resource
    private RuleConverter ruleConverter;

    @Resource
    private OpaRepository opaRepository;

    @Resource
    private GlobalVariableConfigMapper globalVariableConfigMapper;

    @Resource
    private RuleGroupMapper ruleGroupMapper;

    @Resource
    private RuleFactory ruleFactory;

    @Resource
    private RuleTypeMapper ruleTypeMapper;

    @Resource
    private GlobalVariableConfigRuleRelMapper globalVariableConfigRuleRelMapper;

    @Value("${cloudrec.rule.path}")
    private String rulePath;


    @Override
    public List<RuleAgg> findAll() {
        List<RulePO> all = ruleMapper.findAll();
        return all.stream().map(r -> this.findByRuleId(r.getId())).toList();
    }

    @Override
    public List<RuleAgg> findByIdList(List<Long> idList) {
        List<RulePO> all = ruleMapper.findByIdList(idList);
        return all.stream().map(r -> this.findByRuleId(r.getId())).toList();
    }

    @Override
    public List<RuleAgg> findAll(String platform) {
        RuleDTO dto = RuleDTO.builder().platform(platform).status(Status.valid.name()).build();
        List<RulePO> all = ruleMapper.findList(dto);
        List<RuleAgg> list = all.stream().map(r -> this.findByRuleId(r.getId())).toList();
        return list;
    }

    @Override
    public RuleAgg findByRuleId(Long ruleId) {
        // 查询规则
        RulePO rulePO = ruleMapper.selectByPrimaryKey(ruleId);
        if (rulePO == null) {
            return null;
        }

        // 查询策略
        RuleAgg entity = ruleConverter.toEntity(rulePO);
        RuleRegoPO latestOne = ruleRegoMapper.findLatestOne(entity.getId());
        if (latestOne != null) {
            entity.setRegoPolicy(latestOne.getRuleRego());
            entity.setRegoPath(opaRepository.findPackage(latestOne.getRuleRego()));
            entity.replace();
        }

        // 关联变量
        List<GlobalVariableConfigPO> globalVariableConfigPOS = globalVariableConfigMapper.findByRuleId(entity.getId());
        if (CollectionUtils.isNotEmpty(globalVariableConfigPOS)) {
            List<GlobalVariable> globalVariables = Util.map(globalVariableConfigPOS, GlobalVariable::toEntity);
            entity.setGlobalVariables(globalVariables);
        }

        // 关联规则组
        RuleGroupDTO ruleGroupDTO = RuleGroupDTO.builder().ruleIdList(List.of(ruleId)).build();
        List<RuleGroupPO> list = ruleGroupMapper.findList(ruleGroupDTO);
        entity.setRuleGroups(Util.map(list, RuleGroup::toEntity));

        // 查询规则的类型
        List<RuleTypePO> ruleTypes = ruleTypeMapper.findRuleTypeByRuleId(entity.getId());
        entity.setRuleTypeList(Util.map(ruleTypes, RuleTypePO::getTypeName));

        return entity;
    }

    @Override
    public List<RuleAgg> findByGroupId(Long groupId, String status) {
        RuleDTO ruleDTO = RuleDTO.builder().ruleGroupId(groupId).status(status).build();
        List<RulePO> list = ruleMapper.findList(ruleDTO);
        if (CollectionUtils.isEmpty(list)) {
            return Collections.emptyList();
        }
        return list.stream().map(r -> this.findByRuleId(r.getId())).toList();
    }

    @Override
    public void save(RuleAgg ruleAgg) {
        RulePO rulePO = ruleConverter.toPo(ruleAgg);
        if (ruleAgg.getId() != null) {
            ruleMapper.updateByPrimaryKeySelective(rulePO);
        } else {
            ruleMapper.insertSelective(rulePO);
        }
    }

    /**
     * 关联规则和全局变量
     *
     * @param ruleId
     * @param globalVariables
     */
    @Override
    public void relatedGlobalVariables(Long ruleId, List<GlobalVariable> globalVariables) {
        // 4. Save the mapping relationship between rules and global variables
        globalVariableConfigRuleRelMapper.delByRuleId(ruleId);
        for (GlobalVariable globalVariable : globalVariables) {
            GlobalVariableConfigPO globalVariableConfigPO = globalVariableConfigMapper.findByPath(globalVariable.getPath());
            if (globalVariableConfigPO == null) {
                globalVariableConfigPO = new GlobalVariableConfigPO();
                globalVariableConfigPO.setPath(globalVariable.getPath());
                globalVariableConfigPO.setName(globalVariable.getName());
                globalVariableConfigPO.setData(globalVariable.getData());
                globalVariableConfigPO.setStatus(globalVariable.getStatus());
                globalVariableConfigMapper.insertSelective(globalVariableConfigPO);
            }

            GlobalVariableConfigRuleRelPO globalVariableConfigRuleRelPO = new GlobalVariableConfigRuleRelPO();
            globalVariableConfigRuleRelPO.setGlobalVariableConfigId(globalVariableConfigPO.getId());
            globalVariableConfigRuleRelPO.setRuleId(ruleId);
            globalVariableConfigRuleRelMapper.insertSelective(globalVariableConfigRuleRelPO);
        }
    }

    @Override
    public void saveOrgRule(RuleAgg ruleAgg) {
        // Update rule metadata information
        RulePO rulePO = ruleConverter.toPo(ruleAgg);
        if (ruleAgg.getId() == null) {
            ruleMapper.insertSelective(rulePO);
        } else {
            RulePO existRule = ruleMapper.findOne(ruleAgg.getRuleCode());
            if (existRule != null) {
                rulePO.setId(existRule.getId());
                rulePO.setGmtModified(new Date());
                ruleMapper.updateByPrimaryKeySelective(rulePO);
            } else {
                // When RuleCode is not empty,But not exist in database, still should insert
                ruleMapper.insertSelective(rulePO);
            }
        }

        // Update rule types
        if (CollectionUtils.isNotEmpty(ruleAgg.getRuleTypeList())) {
            ruleTypeRelMapper.del(rulePO.getId());
            for (String ruleType : ruleAgg.getRuleTypeList()) {
                RuleTypePO ruleTypePO = ruleTypeMapper.findByTypeName(ruleType);
                if (ruleTypePO == null) {
                    log.warn("ruleType not found, ruleType: {}", ruleType);
                    continue;
                }
                RuleTypeRelPO ruleTypeRelPO = new RuleTypeRelPO();
                ruleTypeRelPO.setRuleTypeId(ruleTypePO.getId());
                ruleTypeRelPO.setRuleId(rulePO.getId());
                ruleTypeRelMapper.insertSelective(ruleTypeRelPO);
            }
        }

        // Update policy
        RuleRegoPO existPO = ruleRegoMapper.findLatestOne(ruleAgg.getId());
        if (existPO != null && Objects.equals(existPO.getRuleRego(), ruleAgg.getRegoPolicy())) {
            return;
        }

        RuleRegoPO ruleRegoPO = new RuleRegoPO();
        ruleRegoPO.setPlatform(rulePO.getPlatform());
        ruleRegoPO.setResourceType(rulePO.getResourceType());
        ruleRegoPO.setRuleId(rulePO.getId());
        ruleRegoPO.setRuleRego(ruleAgg.getRegoPolicy());
        ruleRegoPO.setUserId("SYSTEM");

        if (existPO != null) {
            ruleRegoPO.setVersion(existPO.getVersion() + 1);
            ruleRegoMapper.insertSelective(ruleRegoPO);
        } else {
            ruleRegoPO.setVersion(1);
            ruleRegoMapper.insertSelective(ruleRegoPO);
        }
    }


    @Override
    public List<RuleAgg> findRuleListFromGitHub() {
        Path localPath = null;
        try {
            localPath = Files.createTempDirectory("temp");

            GitHubSyncUtil.cloneRepository(MetadataParser.RULE_REPO_URL, localPath);

            return loadAndRelation(localPath);

        } catch (Exception e) {
            log.warn("Error occurred while loading rules: {}", e.getMessage());
        } finally {
            if (localPath != null && Files.exists(localPath)) {
                try {
                    FileUtils.deleteDirectory(localPath.toFile());
                } catch (Exception e) {
                    log.warn("Error occurred while deleting local path: {}", e.getMessage());
                }
            }
        }

        return List.of();
    }


    private List<RuleAgg> loadRuleFile(Path localPath) throws IOException {
        Path rulePath = localPath.resolve(MetadataParser.RULE_FILE_NAME);

        if (!Files.exists(rulePath)) {
            log.warn("Rule directory not found!");
            return List.of();
        }

        // Find the deepest directory
        List<Path> deepestDirs = DirectoryWalkerUtil.findDeepestDirectories(rulePath);

        // Collect rule data
        String dataFilePath = MetadataParser.GLOBAL_VARIABLE.substring(0, MetadataParser.GLOBAL_VARIABLE.length() - 1);
        List<RuleAgg> rules = new ArrayList<>();
        for (Path dir : deepestDirs) {
            // Skip the data path
            if (dir.toString().contains(dataFilePath)) {
                continue;
            }
            Path policyFile = dir.resolve(MetadataParser.REGO_FILE_NAME);
            Path metadataFile = dir.resolve(MetadataParser.METADATA_JSON_FILE_NAME);
            Path globalVariableFile = dir.resolve(MetadataParser.RELATION_JSON_FILE_NAME);
            if (Files.exists(policyFile) && Files.exists(metadataFile) && Files.exists(globalVariableFile)) {
                // Parse metadata
                MetadataParser.Metadata metadata = MetadataParser.parseMetaDataJson(metadataFile);
                // Parse policy
                String policy = new String(Files.readAllBytes(policyFile));
                // Parse rel global variable
                List<String> globalVariablePathList = MetadataParser.parseRelationJson(globalVariableFile);
                if (!MetadataParser.verifyData(metadata, policy)) {
                    continue;
                }

                log.info("find rule: {}", metadata.getCode());
                RuleAgg ruleAgg = ruleFactory.convertToRule(metadata, policy, globalVariablePathList);
                rules.add(ruleAgg);
            }
        }
        return rules;
    }

    private List<Map<String, Object>> loadGlobalVariables(Path localPath) {
        Path globalVariablePath = localPath.resolve(MetadataParser.GLOBAL_VARIABLE);

        if (!Files.exists(globalVariablePath)) {
            log.warn("global variable directory not found!");
            return List.of();
        }

        List<Map<String, Object>> globalVariables = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(globalVariablePath)) {
            paths.filter(Files::isRegularFile)
                    .forEach(filePath -> {
                        try {
                            Map<String, Object> map = MetadataParser.parseGlobalVariableJson(filePath);
                            globalVariables.add(map);
                        } catch (IOException e) {
                            log.warn("failed to read global variable file: {}", filePath);
                        }
                    });
        } catch (IOException e) {
            log.warn("failed to read global variable directory: {}", globalVariablePath);
        }

        return globalVariables;
    }


    public List<RuleAgg> findRuleListFromLocalFile() {
        Path localPath = Paths.get(rulePath);

        try {
            return loadAndRelation(localPath);
        } catch (Exception e) {
            log.error("Failed to load local rules: {}", e.getMessage(), e);
            return List.of();
        }
    }


    /**
     * 加载并关联规则
     *
     * @param localPath
     * @return
     * @throws IOException
     */
    private List<RuleAgg> loadAndRelation(Path localPath) throws IOException {
        List<RuleAgg> ruleAggs = loadRuleFile(localPath);
        log.info("rule size is >>>: {}", ruleAggs.size());
        List<Map<String, Object>> globalVariables = loadGlobalVariables(localPath);
        log.info("global variable size is >>>: {}", globalVariables.size());

        // 关联两者
        for (RuleAgg ruleAgg : ruleAggs) {
            if (ruleAgg.getGlobalVariables() == null) {
                continue;
            }

            for (GlobalVariable globalVariable : ruleAgg.getGlobalVariables()) {
                for (Map<String, Object> globalVariableMap : globalVariables) {
                    if (globalVariableMap.get(globalVariable.getPath()) != null) {
                        globalVariable.setData(JSON.toJSONString(globalVariableMap.get(globalVariable.getPath())));
                        globalVariable.setName(globalVariable.getPath().replaceAll("_", " "));
                        globalVariable.setStatus(Status.valid.name());
                    }
                }
            }
        }

        return ruleAggs;
    }

    /**
     * Is there a new rule
     *
     * @return true: there is a new rule, false: no new rule
     */
    @Override
    public int existNewRule() {
        int newRuleCount = 0;
        List<RuleAgg> ruleList = findRuleListFromGitHub();
        for (RuleAgg rule : ruleList) {
            RulePO existRule = ruleMapper.findOne(rule.getRuleCode());
            if (existRule == null) {
                newRuleCount++;
            }
        }

        return newRuleCount;
    }
}
