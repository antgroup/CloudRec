package com.alipay.api.web.account;


import com.alipay.application.service.account.CollectorRecordService;
import com.alipay.application.share.request.account.GetCollectorRecordListRequest;
import com.alipay.application.share.vo.ApiResponse;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CollectorLogDetailVO;
import com.alipay.application.share.vo.account.CollectorRecordVO;
import jakarta.annotation.Resource;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/*
 *@title CollectorRecordController
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/13 09:59
 */
@Slf4j
@RestController
@RequestMapping("/api/cloudAccount/collectorRecord")
public class CollectorRecordController {

    @Resource
    private CollectorRecordService collectorRecordService;


    @PostMapping("/getCollectorRecordList")
    public ApiResponse<ListVO<CollectorRecordVO>> getCollectorRecordList(@RequestBody GetCollectorRecordListRequest request, @Valid BindingResult result) {
        ListVO<CollectorRecordVO> recordList = collectorRecordService.getCollectorRecordList(request);
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        return new ApiResponse<>(recordList);
    }

    @PostMapping("/getCollectorRecordDetail")
    public ApiResponse<CollectorLogDetailVO> getCollectorRecordDetail(@RequestBody GetCollectorRecordListRequest request) {
        CollectorLogDetailVO collectorRecordDetail = collectorRecordService.getCollectorRecordDetail(request);
        return new ApiResponse<>(collectorRecordDetail);
    }

    @PostMapping("/getErrorCodeList")
    public ApiResponse<List<Map<String, Integer>>> getErrorCodeList(@RequestBody GetCollectorRecordListRequest request, @Valid BindingResult result) {
        if (result.hasErrors()) {
            return new ApiResponse<>(result);
        }
        return new ApiResponse<>(collectorRecordService.getErrorCodeList(request));
    }
}
