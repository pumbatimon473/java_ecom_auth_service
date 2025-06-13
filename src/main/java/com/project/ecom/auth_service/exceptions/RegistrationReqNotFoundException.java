package com.project.ecom.auth_service.exceptions;

public class RegistrationReqNotFoundException extends RuntimeException {
    public RegistrationReqNotFoundException(Long reqId) {
        super("No seller registration request found with id: " + reqId);
    }
}
