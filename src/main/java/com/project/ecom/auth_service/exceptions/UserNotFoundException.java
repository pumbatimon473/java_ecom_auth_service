package com.project.ecom.auth_service.exceptions;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String email) {
        super("No user exists with email: " + email);
    }

    public UserNotFoundException(Long userId) {
        super("No user exists with id: " + userId);
    }
}
