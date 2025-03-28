package com.project.ecom.auth_service.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
public class User extends BaseModel {
    private String email;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)  // Addressing LazyInitializationException while fetching the GrantedAuthorities
    @JoinTable(
            name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private List<Role> roles;
}
