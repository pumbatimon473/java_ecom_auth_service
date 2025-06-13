package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.models.ApprovalStatus;
import com.project.ecom.auth_service.models.SellerRegistrationRequest;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterSellerResponseDto {
    private Long requestId;
    private String name;
    private String email;
    private String panNumber;
    private String gstRegNumber;
    private ApprovalStatus approvalStatus;

    public static RegisterSellerResponseDto from(SellerRegistrationRequest sellerRegistrationRequest) {
        RegisterSellerResponseDto responseDto = new RegisterSellerResponseDto();
        responseDto.setRequestId(sellerRegistrationRequest.getUser().getId());
        responseDto.setName(String.format("%s %s", sellerRegistrationRequest.getUser().getFirstName(), sellerRegistrationRequest.getUser().getLastName()));
        responseDto.setEmail(sellerRegistrationRequest.getUser().getEmail());
        responseDto.setPanNumber(sellerRegistrationRequest.getPanNumber());
        responseDto.setGstRegNumber(sellerRegistrationRequest.getGstRegNumber());
        responseDto.setApprovalStatus(sellerRegistrationRequest.getApprovalStatus());
        return responseDto;
    }
}
