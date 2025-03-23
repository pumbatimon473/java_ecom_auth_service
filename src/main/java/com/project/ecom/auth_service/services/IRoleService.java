package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.models.Role;

import java.util.List;

public interface IRoleService {
    Role createNewRole(String name);

    void setRolesToUser(List<String> roleNames, Long userId);
}
