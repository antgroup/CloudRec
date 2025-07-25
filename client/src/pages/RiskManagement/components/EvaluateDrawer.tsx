import { JSONEditor } from '@/components/Editor';
import { queryRiskDetailById } from '@/services/risk/RiskController';
import { useIntl, useRequest } from '@umijs/max';
import { Drawer } from 'antd';
import React, { Dispatch, SetStateAction, useEffect, useState } from 'react';

interface IEvaluateDrawerProps {
  evaluateDrawerVisible: boolean;
  setEvaluateDrawerVisible: Dispatch<SetStateAction<boolean>>;
  riskDrawerInfo: Record<string, any>;
}

// Testing Details
const EvaluateDrawer: React.FC<IEvaluateDrawerProps> = (props) => {
  // Component Props
  const { evaluateDrawerVisible, riskDrawerInfo, setEvaluateDrawerVisible } =
    props;

  // Intl API
  const intl = useIntl();

  const [evaluateEditor, setEvaluateEditor] = useState(``);

  const initDrawer = (): void => {
    setEvaluateDrawerVisible(false);
    setEvaluateEditor(``);
  };

  // Detecting detailed data
  const { loading: riskInfoLoading, run: requestRiskDetailById }: any =
    useRequest(
      (id) => {
        return queryRiskDetailById({ riskId: id });
      },
      {
        manual: true,
        formatResult: (r: any) => {
          const { content } = r;
          const evaluateJSON = content?.result
            ? JSON.parse(content?.result)
            : {};
          setEvaluateEditor(JSON.stringify(evaluateJSON, null, 4) || '');
          return r.content || {};
        },
      },
    );

  const onClickCloseDrawerForm = (): void => {
    initDrawer();
  };

  useEffect((): void => {
    if (evaluateDrawerVisible && riskDrawerInfo?.id) {
      requestRiskDetailById(riskDrawerInfo.id);
    }
  }, [evaluateDrawerVisible, riskDrawerInfo]);

  return (
    <Drawer
      title={intl.formatMessage({
        id: 'risk.module.text.testing.situation',
      })}
      width={'50%'}
      destroyOnClose
      open={evaluateDrawerVisible}
      onClose={onClickCloseDrawerForm}
      loading={riskInfoLoading}
    >
      <JSONEditor
        editorKey="evaluateEditor"
        value={evaluateEditor}
        readOnly={true}
        editorStyle={{ height: '100%' }}
      />
    </Drawer>
  );
};

export default EvaluateDrawer;
