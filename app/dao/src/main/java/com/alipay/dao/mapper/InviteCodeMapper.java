package com.alipay.dao.mapper;

import com.alipay.dao.po.InviteCodePO;

public interface InviteCodeMapper {
    int deleteByPrimaryKey(Long id);

    int insertSelective(InviteCodePO row);

    InviteCodePO selectByPrimaryKey(Long id);

    int updateByPrimaryKeySelective(InviteCodePO row);

    InviteCodePO findOne(String code);
}