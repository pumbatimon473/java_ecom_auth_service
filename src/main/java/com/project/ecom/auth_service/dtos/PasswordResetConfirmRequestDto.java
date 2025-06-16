package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.password_validator.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetConfirmRequestDto {
    @NotBlank(message = "A valid password is required")
    @ValidPassword
    private String newPassword;
    @NotBlank(message = "A valid reset token is required")
    private String resetToken;
}
