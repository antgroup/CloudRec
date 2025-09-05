/**
 * 表格行鼠标悬浮效果的通用工具函数
 */
export const createTableRowHoverEffects = () => {
  return {
    style: { cursor: 'pointer' },
    onMouseEnter: (e: React.MouseEvent<HTMLTableRowElement>) => {
      e.currentTarget.style.backgroundColor = '#f5f5f5';
      e.currentTarget.style.transform = 'scale(1.01)';
      e.currentTarget.style.transition = 'all 0.2s ease';
      e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
    },
    onMouseLeave: (e: React.MouseEvent<HTMLTableRowElement>) => {
      e.currentTarget.style.backgroundColor = '';
      e.currentTarget.style.transform = 'scale(1)';
      e.currentTarget.style.boxShadow = '';
    },
  };
};

/**
 * 创建表格行点击和悬浮效果的配置
 * @param handleRowClick 行点击处理函数
 * @returns onRow配置对象
 */
export const createTableRowConfig = (handleRowClick: (record: any) => void) => {
  return (record: any) => ({
    onClick: () => handleRowClick(record),
    ...createTableRowHoverEffects(),
  });
};