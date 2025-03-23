package com.project.ecom.auth_service.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity
public class Session extends BaseModel {
    private String token;
    private Date expiryDate;

    @ManyToOne  // Unidirectional relation
    @JoinColumn(name = "user_id")
    private User user;

    @Enumerated(EnumType.STRING)
    private SessionStatus status;
}
