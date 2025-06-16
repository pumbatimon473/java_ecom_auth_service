package com.project.ecom.auth_service.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetRequestDto {
    @NotBlank(message = "Email is required")
    @Email(message = "Not a valid email")
    private String email;
}
