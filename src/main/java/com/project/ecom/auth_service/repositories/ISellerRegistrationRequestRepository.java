package com.project.ecom.auth_service.repositories;

import com.project.ecom.auth_service.models.SellerRegistrationRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ISellerRegistrationRequestRepository extends JpaRepository<SellerRegistrationRequest, Long> {
    Optional<SellerRegistrationRequest> findByUserEmail(String email);
}
