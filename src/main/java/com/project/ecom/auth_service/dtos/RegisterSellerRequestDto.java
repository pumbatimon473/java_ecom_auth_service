package com.project.ecom.auth_service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterSellerRequestDto {
    private String panNumber;
    private String gstRegNumber;
}
