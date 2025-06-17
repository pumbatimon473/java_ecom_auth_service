package com.project.ecom.auth_service.controllers;

import com.project.ecom.auth_service.dtos.RegisterSellerRequestDto;
import com.project.ecom.auth_service.dtos.RegisterSellerResponseDto;
import com.project.ecom.auth_service.dtos.UpdateSellerRegReqDto;
import com.project.ecom.auth_service.models.ApprovalStatus;
import com.project.ecom.auth_service.models.SellerRegistrationRequest;
import com.project.ecom.auth_service.services.ISellerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api")
@Deprecated
public class SellerController {
    private final ISellerService sellerService;

    @Autowired
    public SellerController(ISellerService sellerService) {
        this.sellerService = sellerService;
    }

    @PostMapping("/seller/register")
    public ResponseEntity<RegisterSellerResponseDto> register(@RequestBody RegisterSellerRequestDto requestDto, @RequestHeader(name = HttpHeaders.AUTHORIZATION) String accessToken) throws ParseException {
        System.out.println(":: ACCESS TOKEN :: " + accessToken);
        SellerRegistrationRequest sellerRegistrationRequest = sellerService.registerAsSeller(requestDto.getPanNumber(), requestDto.getGstRegNumber(), accessToken.replace("Bearer ", ""));
        return ResponseEntity.status(HttpStatus.OK).body(RegisterSellerResponseDto.from(sellerRegistrationRequest));
    }

    @PatchMapping("/admin/seller/request")
    public ResponseEntity<RegisterSellerResponseDto> updateRequestStatus(@RequestBody UpdateSellerRegReqDto requestDto, @AuthenticationPrincipal Jwt jwt) {
        Long updatedBy = (Long) jwt.getClaim("user_id");
        System.out.println(":: UPDATED BY :: " + updatedBy);
        SellerRegistrationRequest sellerRegistrationRequest = this.sellerService.updateRequestStatus(requestDto.getRequestId(), requestDto.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(RegisterSellerResponseDto.from(sellerRegistrationRequest));
    }
}
