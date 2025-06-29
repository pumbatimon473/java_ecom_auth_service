package com.project.ecom.auth_service.configs;

import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.repositories.IUserRepository;
import com.project.ecom.auth_service.services.IRoleService;
import com.project.ecom.auth_service.services.IUserService;
import jakarta.transaction.Transactional;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

import java.util.List;
import java.util.Optional;

@Configuration
public class DefaultAdminLoader {
    private final String adminFirstName = "Gandhi";
    private final String adminLastName = "Bot";
    private final String adminEmail = "gandhi@bot.com";
    private final String adminPassword = "1234";
    private final List<String> ROLES = List.of("ADMIN", "SELLER");

    private final IUserService userService;
    private final IUserRepository userRepo;
    private final IRoleService roleService;

    public DefaultAdminLoader(IUserService userService, IUserRepository userRepo, IRoleService roleService) {
        this.userService = userService;
        this.userRepo = userRepo;
        this.roleService = roleService;
    }

    @Transactional
    @EventListener(ApplicationReadyEvent.class)
    protected void loadAdmin() {
        // register user
        Optional<User> userOptional = this.userRepo.findByEmail(adminEmail.toLowerCase().trim());
        if (userOptional.isEmpty()) {
            try {
                User user = this.userService.register(this.adminEmail, this.adminPassword, this.adminFirstName, this.adminLastName);
                this.roleService.setRolesToUser(ROLES, user.getId());
                System.out.println(":: LOG :: DefaultAdminLoader :: SUCCESS");
            } catch (Exception e) {
                System.out.println(":: LOG :: DefaultAdminLoader :: Unexpected error occurred while registering a user! " + e);
            }
        }

        userOptional.ifPresent(user -> {
            this.roleService.setRolesToUser(ROLES, user.getId());
            System.out.println(":: LOG :: DefaultAdminLoader :: Assigned role to the user");
        });
    }
}
