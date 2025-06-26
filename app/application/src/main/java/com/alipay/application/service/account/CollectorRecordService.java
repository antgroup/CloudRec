package com.alipay.application.service.account;


import com.alipay.application.share.request.account.GetCollectorRecordListRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CollectorLogDetailVO;
import com.alipay.application.share.vo.account.CollectorRecordVO;

import java.util.List;
import java.util.Map;

/*
 *@title CollectorRecordService
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/13 10:02
 */
public interface CollectorRecordService {


    /**
     * 分页查询采集记录列表
     *
     * @param request 查询参数
     * @return 采集记录列表
     */
    ListVO<CollectorRecordVO> getCollectorRecordList(GetCollectorRecordListRequest request);


    /**
     * 查询采集记录详情
     * @param request 查询参数
     * @return 采集记录详情
     */
    CollectorLogDetailVO getCollectorRecordDetail(GetCollectorRecordListRequest request);


    List<Map<String, Integer>> getErrorCodeList(GetCollectorRecordListRequest request);
}
