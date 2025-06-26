import { BASE_URL } from '@/services';
import { request } from '@umijs/max';

/** 获取采集记录列表 */
export async function getCollectorRecordList(
  body?: API.CollectorRecordListRequest,
  options?: { [p: string]: any },
) {
  return request<API.Result_T_>(
    `${BASE_URL}/api/cloudAccount/collectorRecord/getCollectorRecordList`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      data: body,
      ...(options || {}),
    },
  );
}

/** 获取采集记录详情 POST /api/cloudAccount/collectorRecord/getCollectorRecordDetail */
export async function getCollectionRecordDetail(body?: { id: number },
                                                options?: { [p: string]: any }) {
  return request<API.CollectionRecord>(`${BASE_URL}/api/cloudAccount/collectorRecord/getCollectorRecordDetail`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });
}

// getErrorCodeList
export async function getErrorCodeList(body?: { cloudAccountId: string | undefined; platform: string },
                                       options?: { [p: string]: any }) {
  return request<API.CollectionRecord>(`${BASE_URL}/api/cloudAccount/collectorRecord/getErrorCodeList`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    data: body,
    ...(options || {}),
  });

}