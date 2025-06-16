package com.project.ecom.auth_service.repositories;

import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.models.SessionType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Date;
import java.util.Optional;

public interface ISessionRepository extends JpaRepository<Session, Long> {
    Optional<Session> findByUserIdAndToken(Long userId, String token);

    Optional<Session> findByUserIdAndStatusAndTypeAndExpiryDateAfter(Long userId, SessionStatus sessionStatus, SessionType sessionType, Date time);
}
