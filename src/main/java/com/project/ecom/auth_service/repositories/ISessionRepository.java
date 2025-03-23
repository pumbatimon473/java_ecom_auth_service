package com.project.ecom.auth_service.repositories;

import com.project.ecom.auth_service.models.Session;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ISessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByUserIdAndToken(Long userId, String token);
}
