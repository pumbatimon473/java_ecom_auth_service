package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.models.ApprovalStatus;
import com.project.ecom.auth_service.models.SellerRegistrationRequest;

import java.text.ParseException;

public interface ISellerService {
    SellerRegistrationRequest registerAsSeller(String panNumber, String gstRegNumber, String accessToken) throws ParseException;

    SellerRegistrationRequest updateRequestStatus(Long reqId, ApprovalStatus approvalStatus);
}
