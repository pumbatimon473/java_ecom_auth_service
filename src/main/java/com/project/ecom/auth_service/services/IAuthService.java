package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.models.User;

public interface IAuthService {
    User signup(String email, String password);

    Session login(String email, String password);

    void logout(Long userId, String token);

    SessionStatus validate(Long userId, String token);
}
