package com.project.ecom.auth_service.exceptions;

public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException(String role) {
        super("Role does not exist with name: " + role);
    }
}
