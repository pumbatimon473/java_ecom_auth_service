package com.project.ecom.auth_service.configs;

import com.project.ecom.auth_service.exceptions.RoleAlreadyExistsException;
import com.project.ecom.auth_service.services.IRoleService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class StandardRolesLoader {
    private static final Set<String> ROLES = Set.of("ADMIN", "SELLER");

    @Bean
    public CommandLineRunner createRoles(IRoleService roleService) {
        return args -> {
            for(String role : StandardRolesLoader.ROLES) {
                try {
                    roleService.createNewRole(role);
                } catch (RoleAlreadyExistsException e) {
                    System.out.println(":: LOG :: StandardRolesLoader :: Role already exists: " + role);
                }
            }
        };
    }
}
