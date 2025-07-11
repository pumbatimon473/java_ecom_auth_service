package com.project.ecom.auth_service.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDto {
    @Email(message = "Registered email is required")
    private String email;
    @NotBlank(message = "Password is required")
    private String password;
}
