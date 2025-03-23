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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
        List<Role> roles = new ArrayList<>();
        for (String roleName : roleNames) {
            Role role = this.roleRepo.findByNameIgnoreCase(roleName.trim())
                    .orElseThrow(() -> new RoleNotFoundException(roleName.toUpperCase().trim()));
            roles.add(role);
        }
        User user = this.userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        user.setRoles(roles);
        this.userRepo.save(user);
    }
}
