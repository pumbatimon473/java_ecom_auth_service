package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.models.User;

import java.text.ParseException;

public interface IUserService {
    AccessTokenResponse login(String email, String password);

    void changePassword(String email, String oldPassword, String newPassword);

    void resetPassword(String email) throws ParseException;

    void confirmPasswordReset(String newPassword, String resetToken) throws ParseException;

    User register(String email, String password, String firstName, String lastName);
}
