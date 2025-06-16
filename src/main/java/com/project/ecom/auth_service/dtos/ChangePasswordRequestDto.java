package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.password_validator.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ChangePasswordRequestDto {
    @NotBlank(message = "Current password is required")
    private String oldPassword;
    @NotBlank(message = "New password is required")
    @ValidPassword
    private String newPassword;
}
