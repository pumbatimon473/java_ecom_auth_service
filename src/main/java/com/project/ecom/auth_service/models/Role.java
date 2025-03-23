package com.project.ecom.auth_service.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity
public class Role extends BaseModel {
    private String name;

    @ManyToMany(mappedBy = "roles")
    private List<User> users;
}
