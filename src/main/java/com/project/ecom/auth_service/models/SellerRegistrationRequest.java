package com.project.ecom.auth_service.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Deprecated
public class SellerRegistrationRequest extends BaseModel {
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
    private String panNumber;
    private String gstRegNumber;
    @Enumerated(EnumType.STRING)
    private ApprovalStatus approvalStatus;
}
