package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.models.ApprovalStatus;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateSellerRegReqDto {
    private Long requestId;
    private ApprovalStatus status;
}
