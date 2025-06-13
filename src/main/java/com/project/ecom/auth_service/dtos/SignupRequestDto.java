package com.project.ecom.auth_service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequestDto {
    private String email;
    private String password;
    private String firstName;
    private String lastName;
}
