package com.project.ecom.auth_service.exceptions;

public class UserLoginException extends RuntimeException {
    public UserLoginException() {
        super("The provided email id or password is not correct!");
    }
}
