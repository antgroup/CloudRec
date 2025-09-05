package com.alipay.application.share.vo.user;


import com.alipay.dao.po.InviteCodePO;
import lombok.Getter;
import lombok.Setter;

/*
 *@title InvitationCodeVO
 *@description
 *@author suitianshuang
 *@version 1.0
 *@create 2025/7/25 16:32
 */
@Getter
@Setter
public class InvitationCodeVO {

    private String inviter;

    private String tenantName;

    private String invitationCode;

    public static InvitationCodeVO toVO(InviteCodePO inviteCodePO) {
        InvitationCodeVO invitationCodeVO = new InvitationCodeVO();
        invitationCodeVO.setInvitationCode(inviteCodePO.getCode());
        return invitationCodeVO;
    }
}
