import Disposition from '@/components/Disposition';
import AccountModal from '@/pages/CloudAccount/AccountList/components/AccountModal';
import EditModalForm from '@/pages/CloudAccount/AccountList/components/EditModalForm';
import {
  removeCloudAccount,
  updateCloudAccountStatus,
  createCollectTask,
} from '@/services/account/AccountController';
import { accountURLMap } from '@/utils/const';
import { obtainPlatformEasyName } from '@/utils/shared';
import { history, useIntl, useModel } from '@umijs/max';
import { SyncOutlined, CloudSyncOutlined } from '@ant-design/icons';
import {
  Button,
  Col,
  Divider,
  Flex,
  Image,
  message,
  Popconfirm,
  Row,
  Switch,
  Tooltip,
} from 'antd';
import { MessageType } from 'antd/es/message/interface';
import { useRef, useState } from 'react';
import styles from '../../index.less';

interface IAccountCard {
  account: API.CloudAccountResult;
  requestInitData: () => Promise<void>;
  requestCurrentData: () => Promise<void>;
}

const AccountCard = (props: IAccountCard) => {
  // Component Props
  const { account, requestInitData, requestCurrentData } = props;
  const {
    id,
    platform,
    cloudAccountId,
    alias,
    accountStatus,
    tenantName,
    resourceCount,
    riskCount,
    lastScanTime,
    collectorStatus,
    gmtCreate,
    gmtModified,
  } = account;
  // Platform Rule Group List
  const { platformList } = useModel('rule');
  // Message API
  const [messageApi, contextHolder] = message.useMessage();
  // Intl API
  const intl = useIntl();
  // New | Edit Modal Form Visible
  const [editFormVisible, setEditFormVisible] = useState<boolean>(false);
  // Cloud account information
  const accountInfoRef = useRef<any>({});
  // Account Drawer
  const [accountModalVisible, setAccountModalVisible] =
    useState<boolean>(false);
  // Cloud account information
  const accountModalRef = useRef<any>({});

  // Disable rule modification status
  const onClickChangeAccountStatus = async (
    cloudAccountId: string,
    accountStatus: string,
  ): Promise<void> => {
    const postBody = {
      cloudAccountId,
      accountStatus,
    };
    const res = await updateCloudAccountStatus(postBody);
    if (res.code === 200 || res.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.edit.success' }),
      );
      await requestCurrentData();
    }
  };

  // Delete cloud account
  const onClickRemoveCloudAccount = async (): Promise<void> => {
    const hide: MessageType = messageApi.loading(
      intl.formatMessage({ id: 'common.message.text.delete.loading' }),
    );
    const result: API.Result_String_ = await removeCloudAccount({ id: id! });
    hide();
    if (result.code === 200 || result.msg === 'success') {
      messageApi.success(
        intl.formatMessage({ id: 'common.message.text.delete.success' }),
      );
      await requestInitData();
    }
  };

  return (
    <>
      {contextHolder}
      <div className={styles['accountCard']}>
        <Flex justify={'space-between'} style={{ width: '100%' }}>
          <Flex>
            <Image
              // @ts-ignore
              src={accountURLMap[platform!]}
              alt="PLATFORM_ICON"
              width={62}
              height={62}
              preview={false}
            />
            <div className={styles['accountNameWrap']}>
              <Disposition
                text={cloudAccountId || '-'}
                maxWidth={100}
                rows={1}
                style={{
                  color: '#262626',
                  fontSize: 17,
                  fontWeight: 500,
                }}
                placement={'topLeft'}
              />
              <Disposition
                text={alias || '-'}
                maxWidth={100}
                rows={1}
                style={{
                  color: '#333',
                  fontSize: 12,
                  margin: '1px 0',
                }}
                placement={'topLeft'}
              />
              <Disposition
                text={obtainPlatformEasyName(platform!, platformList) || '-'}
                maxWidth={100}
                rows={1}
                style={{
                  color: '#999',
                  fontSize: 13,
                }}
                placement={'topLeft'}
              />
            </div>
          </Flex>
          <Tooltip
            title={intl.formatMessage({
              id: 'cloudAccount.extend.title.collect.status',
            })}
          >
            <Switch
              style={{ flexShrink: 0 }}
              checkedChildren={intl.formatMessage({
                id: 'common.button.text.enable',
              })}
              unCheckedChildren={intl.formatMessage({
                id: 'common.button.text.disable',
              })}
              checked={accountStatus === 'valid'}
              onClick={() =>
                onClickChangeAccountStatus(
                  cloudAccountId!,
                  accountStatus === 'valid' ? 'invalid' : 'valid',
                )
              }
            />
          </Tooltip>
        </Flex>

        <Divider className={styles['divider']} />

        <Row gutter={[24, 8]}>
          <Col span={14} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.tenant.attribution',
              })}
            </div>
            <Disposition
              text={tenantName || '-'}
              maxWidth={123}
              rows={1}
              style={{
                color: '#999',
                fontSize: 13,
              }}
              placement={'topLeft'}
            />
          </Col>

          <Col span={10} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.asset.number',
              })}
            </div>
            <Flex align="center" gap={8}>
              <Disposition
                text={resourceCount}
                maxWidth={70}
                rows={1}
                style={{
                  color: '#457AFF',
                  fontSize: 12,
                }}
                link={true}
                onClickCallBackFunc={() =>
                  history.push(
                    `/assetManagement/assetList?platform=${platform}&cloudAccountId=${cloudAccountId}`,
                  )
                }
                placement={'topLeft'}
              />
              <Divider type="vertical" style={{ margin: 0, height: 12 }} />
              <Disposition
                text={riskCount}
                maxWidth={70}
                rows={1}
                style={{
                  color: '#ff4d4f',
                  fontSize: 12,
                }}
                link={true}
                onClickCallBackFunc={() =>
                  history.push(
                    `/riskManagement/riskList?platform=${platform}&cloudAccountId=${cloudAccountId}`,
                  )
                }
                placement={'topLeft'}
              />
            </Flex>
          </Col>
          <Col span={14} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.lastScanTime',
              })}
            </div>
            <Disposition
              text={lastScanTime || '-'}
              maxWidth={123}
              rows={1}
              style={{
                color: '#999',
                fontSize: 13,
              }}
              placement={'topLeft'}
            />
          </Col>
          <Col span={10} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.collection.status',
              })}
            </div>
            <Flex align="center">
              <Disposition
                text={collectorStatus || '-'}
                maxWidth={81}
                rows={1}
                style={{
                  color: '#999',
                  fontSize: 13,
                }}
                placement={'topLeft'}
              />
              {collectorStatus === '扫描中' ? (
                <SyncOutlined
                  style={{ marginLeft: 8, fontSize: 13, color: '#1677FF' }}
                  spin
                />
              ) : collectorStatus === '待扫描' ? (
                <Popconfirm
                  title={intl.formatMessage({ id: 'cloudAccount.extend.collection.popconfirm' })}
                  onConfirm={async () => {
                    const res = await createCollectTask({ cloudAccountId });
                    if (res.code === 200 || res.msg === 'success') {
                      messageApi.success(
                        intl.formatMessage({ id: 'common.message.text.add.success' })
                      );
                      await requestCurrentData();
                    }
                  }}
                  okText={intl.formatMessage({ id: 'common.button.text.ok' })}
                  cancelText={intl.formatMessage({ id: 'common.button.text.cancel' })}
                >
                  <CloudSyncOutlined
                    style={{ marginLeft: 8, cursor: 'pointer', fontSize: 13, color: '#1677FF' }}
                  />
                </Popconfirm>
              ) : null}
            </Flex>
          </Col>
          <Col span={24} className={styles['propertyWrap']}>
            <div className={styles['propertyName']}>
              {intl.formatMessage({
                id: 'cloudAccount.extend.title.createAndUpdateTime',
              })}
            </div>
            <Disposition
              text={gmtCreate || '-'}
              maxWidth={228}
              rows={1}
              style={{
                color: '#999',
                fontSize: 13,
              }}
              placement={'topLeft'}
            />
            <Disposition
              text={gmtModified || '-'}
              maxWidth={228}
              rows={1}
              style={{
                color: '#999',
                fontSize: 13,
                margin: '2px 0 16px 0',
              }}
            />
          </Col>
        </Row>

        <Flex style={{ width: '100%' }} justify={'center'}>
          <Popconfirm
            title={intl.formatMessage({
              id: 'common.button.text.delete.confirm',
            })}
            onConfirm={() => onClickRemoveCloudAccount()}
            okText={intl.formatMessage({
              id: 'common.button.text.ok',
            })}
            cancelText={intl.formatMessage({
              id: 'common.button.text.cancel',
            })}
          >
            <Button
              type={'primary'}
              style={{
                width: 64,
                height: 30,
                borderRadius: 4,
                backgroundColor: '#FFF2F3',
                color: '#EC4344',
              }}
            >
              {intl.formatMessage({
                id: 'common.button.text.delete',
              })}
            </Button>
          </Popconfirm>
          <Button
            size={'small'}
            type={'primary'}
            style={{
              width: 64,
              height: 30,
              borderRadius: 4,
              backgroundColor: '#E7F1FF',
              color: '#1677FF',
              margin: '0 8px',
            }}
            onClick={(): void => {
              setEditFormVisible(true);
              accountInfoRef.current = {
                ...account,
              };
            }}
          >
            {intl.formatMessage({
              id: 'common.button.text.edit',
            })}
          </Button>
          {/*<Button*/}
          {/*  size={'small'}*/}
          {/*  type="link"*/}
          {/*  target={'_blank'}*/}
          {/*  style={{*/}
          {/*    width: 64,*/}
          {/*    height: 30,*/}
          {/*    borderRadius: 4,*/}
          {/*    backgroundColor: '#E7F1FF',*/}
          {/*    color: '#1677FF',*/}
          {/*  }}*/}
          {/*  onClick={(): void => {*/}
          {/*    setAccountModalVisible(true);*/}
          {/*    accountModalRef.current = {*/}
          {/*      ...account,*/}
          {/*    };*/}
          {/*  }}*/}
          {/*>*/}
          {/*  {intl.formatMessage({*/}
          {/*    id: 'common.button.text.detail',*/}
          {/*  })}*/}
          {/*</Button>*/}
          <Button
            size={'small'}
            type="link"
            style={{
              width: 64,
              height: 30,
              borderRadius: 4,
              backgroundColor: '#E7F1FF',
              color: '#1677FF',
              marginLeft: 8,
            }}
            onClick={(): void => {
              history.push(`/cloudAccount/collectionRecord?platform=${platform}&cloudAccountId=${cloudAccountId}`);
            }}
          >
            {intl.formatMessage({
              id: 'cloudAccount.button.text.collection.record',
            })}
          </Button>
        </Flex>
      </div>

      <EditModalForm // Add | Edit Cloud Account
        editFormVisible={editFormVisible}
        setEditFormVisible={setEditFormVisible}
        accountInfo={accountInfoRef.current}
        requestCurrentData={requestCurrentData}
      />

      <AccountModal // Account details
        accountModalVisible={accountModalVisible}
        setAccountModalVisible={setAccountModalVisible}
        accountModalInfo={accountModalRef.current}
      />
    </>
  );
};
export default AccountCard;
