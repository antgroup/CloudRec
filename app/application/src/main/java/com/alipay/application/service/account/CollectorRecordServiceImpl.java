package com.alipay.application.service.account;


import com.alipay.application.share.request.account.GetCollectorRecordListRequest;
import com.alipay.application.share.vo.ListVO;
import com.alipay.application.share.vo.account.CollectorLogDetailVO;
import com.alipay.application.share.vo.account.CollectorRecordVO;
import com.alipay.common.exception.BizException;
import com.alipay.dao.dto.CollectorRecordDTO;
import com.alipay.dao.dto.IQueryResourceDTO;
import com.alipay.dao.mapper.*;
import com.alipay.dao.po.*;
import jakarta.annotation.Resource;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/*
 *@title CollectorRecordServiceImpl
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/6/13 10:07
 */
@Service
public class CollectorRecordServiceImpl implements CollectorRecordService {

    @Resource
    private CollectorRecordMapper collectorRecordMapper;

    @Resource
    private CollectorLogMapper collectorLogMapper;

    @Resource
    private CloudAccountMapper cloudAccountMapper;

    @Resource
    private ResourceMapper resourceMapper;

    @Resource
    private CloudResourceInstanceMapper cloudResourceInstanceMapper;

    /**
     * 分页查询采集记录列表
     *
     * @param request 查询参数
     * @return 采集记录列表
     */
    @Override
    public ListVO<CollectorRecordVO> getCollectorRecordList(GetCollectorRecordListRequest request) {
        ListVO<CollectorRecordVO> listVO = new ListVO<>();
        CollectorRecordDTO dto = CollectorRecordDTO.builder()
                .cloudAccountId(request.getCloudAccountId())
                .platform(request.getPlatform())
                .errorCode(request.getErrorCode())
                .startTimeArray(request.getStartTimeArray())
                .build();
        dto.setPage(request.getPage());
        dto.setSize(request.getSize());
        dto.setOffset();
        int count = collectorRecordMapper.findCount(dto);
        if (count == 0) {
            return listVO;
        }

        List<CollectorRecordPO> list = collectorRecordMapper.findList(dto);
        List<CollectorRecordVO> result = new ArrayList<>(list.stream().map(CollectorRecordVO::build).toList());

        // set percent
        for (CollectorRecordVO recordVO : result){
            IQueryResourceDTO iQueryResourceDTO = IQueryResourceDTO.builder().cloudAccountId(recordVO.getCloudAccountId()).build();
            List<CloudResourceInstancePO> resouceList = cloudResourceInstanceMapper.findByCond(iQueryResourceDTO);
            recordVO.setPercent("0.00");
            if (CollectionUtils.isNotEmpty(resouceList)) {
                int total = resouceList.size();
                int deleteTotal = resouceList.stream().filter(item -> item.getDeletedAt() != null).toList().size();
                recordVO.setPercent(String.format("%.2f", (double) (total - deleteTotal) / total * 100));
            }
        }


        listVO.setTotal(count);
        listVO.setData(result);
        return listVO;
    }

    /**
     * Query the details of the collect record
     *
     * @param request param
     * @return Collection record details
     */
    @Override
    public CollectorLogDetailVO getCollectorRecordDetail(GetCollectorRecordListRequest request) {
        List<CollectorLogPO> list = collectorLogMapper.findList(request.getId());
        if (list.isEmpty()) {
            throw new BizException("The record does not exist");
        }

        CloudAccountPO cloudAccountPO = cloudAccountMapper.findByCloudAccountId(list.get(0).getCloudAccountId());
        if (cloudAccountPO == null) {
            throw new BizException("The cloud account does not exist");
        }

        Map<String, List<CollectorLogPO>> map = list.stream().collect(Collectors.groupingBy(CollectorLogPO::getResourceType));

        CollectorLogDetailVO base = new CollectorLogDetailVO();
        // base info
        base.setPlatform(cloudAccountPO.getPlatform());
        base.setCloudAccountId(cloudAccountPO.getCloudAccountId());
        base.setAlias(cloudAccountPO.getAlias());

        List<CollectorLogDetailVO.ErrorDetail> errorDetails = new ArrayList<>();
        for (Map.Entry<String, List<CollectorLogPO>> entry : map.entrySet()) {
            // error detail
            CollectorLogDetailVO.ErrorDetail errorDetail = new CollectorLogDetailVO.ErrorDetail();
            errorDetail.setResourceType(entry.getKey());
            ResourcePO resourcePO = resourceMapper.findOne(cloudAccountPO.getPlatform(), entry.getKey());
            if (resourcePO != null) {
                errorDetail.setResourceTypeName(resourcePO.getResourceName());
            }

            List<CollectorLogDetailVO.ErrorDetailItem> detailItems = new ArrayList<>();
            // error detail item
            for (CollectorLogPO collectorLogPO : entry.getValue()) {
                CollectorLogDetailVO.ErrorDetailItem errorDetailItem = new CollectorLogDetailVO.ErrorDetailItem();
                errorDetailItem.setDescription(collectorLogPO.getDescription());
                errorDetailItem.setMessage(collectorLogPO.getMessage());
                errorDetailItem.setTime(collectorLogPO.getTime());
                detailItems.add(errorDetailItem);
            }
            errorDetail.setErrorDetailItems(detailItems);
            errorDetails.add(errorDetail);
        }

        base.setErrorDetails(errorDetails);

        return base;
    }

    @Override
    public List<Map<String, Integer>> getErrorCodeList(GetCollectorRecordListRequest request) {
        return collectorLogMapper.listErrorCode(request.getPlatform(), request.getCloudAccountId());
    }
}
