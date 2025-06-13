package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.exceptions.UserAlreadyExistsException;
import com.project.ecom.auth_service.exceptions.UserLoginException;
import com.project.ecom.auth_service.exceptions.UserNotFoundException;
import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.repositories.ISessionRepository;
import com.project.ecom.auth_service.repositories.IUserRepository;
import com.project.ecom.auth_service.utils.JwtTokenBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Optional;

@Service
public class AuthService implements IAuthService {
    private IUserRepository userRepo;
    private ISessionRepository sessionRepo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(IUserRepository userRepo, ISessionRepository sessionRepo, @Qualifier("passwordEncoder") PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.sessionRepo = sessionRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User signup(String email, String password, String firstName, String lastName) {
        Optional<User> userOptional = this.userRepo.findByEmail(email);
        if (userOptional.isPresent())
            throw new UserAlreadyExistsException(email);
        // create a new user
        User user = new User();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        return this.userRepo.save(user);
    }

    @Override
    public Session login(String email, String password) {
        User user = this.userRepo.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(email));
        if (!passwordEncoder.matches(password, user.getPassword()))
            throw new UserLoginException();
        // create a new user session
        Session session = new Session();
        session.setUser(user);
        session.setStatus(SessionStatus.ACTIVE);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, 1);
        session.setExpiryDate(calendar.getTime());

        session.setToken(JwtTokenBuilder.from(user));  // Using jjwt
        return this.sessionRepo.save(session);
    }

    @Override
    public void logout(Long userId, String token) {
        Optional<Session> sessionOptional = this.sessionRepo.findByUserIdAndToken(userId, token);
        if (sessionOptional.isPresent()) {
            sessionOptional.get().setStatus(SessionStatus.LOGGED_OUT);
            this.sessionRepo.save(sessionOptional.get());
        }
    }

    @Override
    public SessionStatus validate(Long userId, String token) {
        Optional<Session> sessionOptional = this.sessionRepo.findByUserIdAndToken(userId, token);
        if (sessionOptional.isEmpty())
            return SessionStatus.INVALID;
        // check session status
        if (sessionOptional.get().getExpiryDate().compareTo(Calendar.getInstance().getTime()) <= 0)
            return SessionStatus.EXPIRED;
        // return the current session status: ACTIVE | LOGGED_OUT
        return sessionOptional.get().getStatus();
    }
}
