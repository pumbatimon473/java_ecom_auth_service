package com.project.ecom.auth_service.exceptions;

import org.apache.commons.lang3.StringUtils;

public class RoleAlreadyExistsException extends RuntimeException {
    public RoleAlreadyExistsException(String name) {
        super("Role already exists with name: " + StringUtils.toRootUpperCase(name));
    }
}
