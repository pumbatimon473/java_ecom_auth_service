package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.exceptions.RoleAlreadyExistsException;
import com.project.ecom.auth_service.exceptions.RoleNotFoundException;
import com.project.ecom.auth_service.exceptions.UserNotFoundException;
import com.project.ecom.auth_service.models.Role;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.repositories.IRoleRepository;
import com.project.ecom.auth_service.repositories.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class RoleService implements IRoleService {
    private IRoleRepository roleRepo;
    private IUserRepository userRepo;

    @Autowired
    public RoleService(IRoleRepository roleRepo, IUserRepository userRepo) {
        this.roleRepo = roleRepo;
        this.userRepo = userRepo;
    }

    @Override
    public Role createNewRole(String name) {
        name = name.toUpperCase().trim();
        Optional<Role> roleOptional = this.roleRepo.findByNameIgnoreCase(name);
        if (roleOptional.isPresent())
            throw new RoleAlreadyExistsException(name);
        // create a new role
        Role role = new Role();
        role.setName(name);
        return this.roleRepo.save(role);
    }

    @Override
    public void setRolesToUser(List<String> roleNames, Long userId) {
        Set<Role> roles = getRoles(roleNames);
        User user = this.userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        user.setRoles(new ArrayList<>(roles));
        this.userRepo.save(user);
    }

    private Set<Role> getRoles(List<String> roleNames) {
        Set<String> uniqueRoleNames = roleNames.stream().map(name -> name.toLowerCase().trim()).collect(Collectors.toSet());
        Set<Role> roles = new HashSet<>();
        for (String roleName : uniqueRoleNames) {
            Role role = this.roleRepo.findByNameIgnoreCase(roleName.trim())
                    .orElseThrow(() -> new RoleNotFoundException(roleName.toUpperCase().trim()));
            roles.add(role);
        }
        return roles;
    }

    @Override
    public void addRolesToUser(List<String> roleNames, Long userId) {
        Set<Role> roles = getRoles(roleNames);
        User user = this.userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        List<Role> userRoles = user.getRoles();
        if (userRoles == null) userRoles = new ArrayList<>();
        roles.addAll(userRoles);
        user.setRoles(new ArrayList<>(roles));
        this.userRepo.save(user);
    }
}
