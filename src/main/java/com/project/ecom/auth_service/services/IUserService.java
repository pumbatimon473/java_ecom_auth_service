package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;

public interface IUserService {
    AccessTokenResponse login(String email, String password);
}
