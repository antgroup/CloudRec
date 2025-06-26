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
package com.alipay.api.web.rule;

import com.alipay.api.config.filter.annotation.aop.AuthenticateToken;
import com.alipay.api.utils.ZipUtil;
import com.alipay.application.service.rule.RuleService;
import com.alipay.application.service.rule.exposed.InitRuleService;
import com.alipay.application.service.rule.job.ScanService;
import com.alipay.application.share.request.base.IdListRequest;
import com.alipay.application.share.request.base.IdRequest;
import com.alipay.application.share.request.rule.ChangeStatusRequest;
import com.alipay.application.share.request.rule.ListRuleRequest;
import com.alipay.application.share.request.rule.LoadRuleFromGithubRequest;
import com.alipay.application.share.request.rule.SaveRuleRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.rule.RuleTypeVO;
import com.alipay.application.share.vo.rule.RuleVO;
import com.alipay.common.enums.RiskLevel;
import com.alipay.common.enums.Status;
import com.alipay.common.exception.BizException;
import com.alipay.common.utils.PreventingSQLJoint;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import org.apache.commons.io.FileUtils;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/*
 *@title RuleController
 *@description 风险管理-规则管理
 *@author jietian
 *@version 1.0
 *@create 2024/6/5 16:44
 */
@RestController
@RequestMapping("/api/rule")
@Validated
@Slf4j
public class RuleController {

    private final ReentrantLock lock = new ReentrantLock();

    @Resource
    private RuleService ruleService;

    @Resource
    private ScanService scanService;

    @Resource
    private InitRuleService initRuleService;

    /**
     * Save the risk rule
     */
    @AuthenticateToken
    @PostMapping("/saveRule")
    public ApiResponse<String> saveRule(@RequestBody SaveRuleRequest req) throws IOException {
        if (req.getRiskLevel() != null) {
            boolean exist = RiskLevel.exist(req.getRiskLevel());
            if (!exist) {
                throw new RuntimeException("level must be High,Medium,Low");
            }
        }
        return ruleService.saveRule(req);
    }

    /**
     * Query risk rule list
     */
    @AuthenticateToken
    @PostMapping("/queryRuleList")
    public ApiResponse<ListVO<RuleVO>> queryRuleList(@RequestBody ListRuleRequest req) {
        PreventingSQLJoint.checkSortParamField(req.getSortParam(), List.of("riskCount"));
        PreventingSQLJoint.checkSortTypeField(req.getSortType());
        return ruleService.queryRuleList(req);
    }

    @GetMapping("/queryAllRuleList")
    public ApiResponse<List<RuleVO>> queryAllRuleList() {
        return new ApiResponse<>(ruleService.queryAllRuleList());
    }

    /**
     * Detection by risk triggering rules
     */
    @PostMapping("/scanByRule")
    public ApiResponse<String> scanByRule(@RequestBody IdRequest request, BindingResult err) throws Exception {
        if (err.hasErrors()) {
            return new ApiResponse<>(err);
        }
        return scanService.scanByRule(request.getId());
    }

    /**
     * Delete risk rules
     */
    @DeleteMapping("/deleteRule")
    public ApiResponse<String> deleteRule(Long id) {
        return ruleService.deleteRule(id);
    }

    /**
     * Modify the rule status
     */
    @PostMapping("/changeRuleStatus")
    public ApiResponse<String> changeRuleStatus(@Validated @RequestBody ChangeStatusRequest changeRuleStatusRequest,
                                                BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        Status.exist(changeRuleStatusRequest.getStatus());

        return ruleService.changeRuleStatus(changeRuleStatusRequest);
    }

    /**
     * Copy rules
     */
    @AuthenticateToken
    @PostMapping("/copyRule")
    public ApiResponse<String> copyRule(@Validated @RequestBody IdRequest req, BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        return ruleService.copyRule(req);
    }

    /**
     * Query rule details interface
     */
    @PostMapping("/queryRuleDetail")
    public ApiResponse<RuleVO> queryRuleDetail(@RequestBody IdRequest idRequest) {
        return ruleService.queryRuleDetail(idRequest);
    }

    /**
     * Query rule details interface
     */
    @GetMapping("/queryRuleTypeList")
    public ApiResponse<List<RuleTypeVO>> queryRuleTypeList() {
        return ruleService.queryRuleTypeList();
    }

    /**
     * Query the list of rule names
     */
    @GetMapping("/queryRuleNameList")
    public ApiResponse<List<String>> queryRuleNameList() {
        List<String> ruleNameList = ruleService.queryRuleNameList();
        return new ApiResponse<>(ruleNameList);
    }

    /**
     * Export all rule files
     *
     * @param response
     */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    @PostMapping("/download")
    public void downloadFiles(HttpServletResponse response, @RequestBody IdListRequest Request) {
        String tempPath = "";
        if (lock.tryLock()) {
            try {
                log.info("Start to download files");
                tempPath = initRuleService.writeRule(Request.getIdList());
                log.info("Rules directory: {}", tempPath);
                ZipUtil.downloadFiles(response, tempPath, "rules");
                log.info("Write rule completed");
                
                // Schedule directory deletion after 2 seconds
                final String finalTempPath = tempPath;
                scheduler.schedule(() -> {
                    try {
                        if (Strings.isNotBlank(finalTempPath)) {
                            File tempDir = new File(finalTempPath);
                            if (tempDir.exists()) {
                                FileUtils.deleteDirectory(tempDir);
                                log.info("Delayed delete temp directory: {}", finalTempPath);
                            }
                        }
                    } catch (Exception e) {
                        log.error("Delayed delete temp directory error", e);
                    }
                }, 2, TimeUnit.SECONDS);
            } finally {
                lock.unlock();
            }
        } else {
            log.info("Resource is locked, operation aborted");
            throw new BizException("Resource is locked, operation aborted");
        }
    }


    // Dynamically obtain sync directory path (development and production environment adaptation)
    private String getRulesDirectory() {
        // Get the path where the class file is located (the development environment is target/classes, and the production environment is JAR file path)
        String codeSourcePath = RuleController.class.getProtectionDomain()
                .getCodeSource().getLocation().getPath();
        codeSourcePath = URLDecoder.decode(codeSourcePath, StandardCharsets.UTF_8);
        File codeSourceFile = new File(codeSourcePath);

        // Determine whether it is a JAR operating environment
        if (codeSourceFile.isFile()) {
            // PROD：“rules” in the directory of the same level of JAR file
            String jarDir = codeSourceFile.getParentFile().getAbsolutePath();
            return jarDir + File.separator + "rules";
        } else {
            // DEV：“rules” in the project root directory
            String projectRoot = System.getProperty("user.dir");
            return projectRoot + File.separator + "rules";
        }
    }

    // initRuleService
    @PostMapping("/loadRuleFromGithub")
    public ApiResponse<String> loadRuleFromGithub(@RequestBody LoadRuleFromGithubRequest request) {
        initRuleService.loadRuleFromGithub(request.getCoverage());
        return ApiResponse.SUCCESS;
    }
}
