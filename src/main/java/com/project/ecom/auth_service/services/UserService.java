package com.project.ecom.auth_service.services;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.dtos.UserInfoResponse;
import com.project.ecom.auth_service.exceptions.UserAlreadyExistsException;
import com.project.ecom.auth_service.exceptions.UserNotFoundException;
import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.models.SessionType;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.repositories.ISessionRepository;
import com.project.ecom.auth_service.repositories.IUserRepository;
import com.project.ecom.auth_service.strategies.TokenGenerationStrategy;
import com.project.ecom.auth_service.utils.JwtTokenBuilder;
import com.project.ecom.auth_service.utils.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService implements IUserService {
    private final AuthenticationManager authenticationManager;
    private final TokenGenerationStrategy tokenGenerationStrategy;
    private final IUserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final ISessionRepository sessionRepo;

    @Autowired
    public UserService(AuthenticationManager authenticationManager, @Qualifier("OAuth2TokenGenerationStrategy") TokenGenerationStrategy tokenGenerationStrategy, IUserRepository userRepo, PasswordEncoder passwordEncoder, ISessionRepository sessionRepo) {
        this.authenticationManager = authenticationManager;
        this.tokenGenerationStrategy = tokenGenerationStrategy;
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.sessionRepo = sessionRepo;
    }

    @Override
    public AccessTokenResponse login(String email, String password) {
        // will throw an exception like BadCredentialsException if the authentication fails
        Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        return this.tokenGenerationStrategy.generateToken(authentication);
    }

    @Override
    public void changePassword(String email, String oldPassword, String newPassword) {
        User user = this.userRepo.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));
        if (!this.passwordEncoder.matches(oldPassword, user.getPassword()))
            throw new BadCredentialsException("Cannot change password. Old password did not match!");
        // change password
        user.setPassword(passwordEncoder.encode(newPassword));
        this.userRepo.save(user);
    }

    @Override
    @Transactional
    public void resetPassword(String email) throws ParseException {
        Optional<User> userOptional = this.userRepo.findByEmail(email);
        if (userOptional.isPresent()) {  // generate password reset token (using JJWT)
            String passwordResetToken = JwtTokenBuilder.generatePasswordResetToken(userOptional.get());
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.MINUTE, 10);
            Date exp = calendar.getTime();
            // invalidate older password reset session
            Session oldSession = this.sessionRepo.findByUserIdAndStatusAndTypeAndExpiryDateAfter(
                    userOptional.get().getId(), SessionStatus.ACTIVE, SessionType.PASSWORD_RESET, Calendar.getInstance().getTime()
            ).orElse(null);
            if (oldSession != null) {
                oldSession.setStatus(SessionStatus.INVALID);
                this.sessionRepo.save(oldSession);
            }
            // create a new session
            Session session = new Session();
            session.setUser(userOptional.get());
            session.setToken(passwordResetToken);
            session.setExpiryDate(exp);
            session.setStatus(SessionStatus.ACTIVE);
            session.setType(SessionType.PASSWORD_RESET);
            this.sessionRepo.save(session);

            System.out.println(":: DEBUG LOG :: Password Reset Token :: " + passwordResetToken);
        }
    }

    @Override
    @Transactional
    public void confirmPasswordReset(String newPassword, String resetToken) throws ParseException {
        if (!JwtUtil.verifySignature(resetToken))
            throw new InvalidOneTimeTokenException("The given token is invalid!");
        Map<String, Object> claims = JwtUtil.getClaims(resetToken);
        String email = (String) claims.get("sub");
        User user = this.userRepo.findByEmail(email).orElseThrow(() -> new UnsupportedOperationException("User is not permitted to perform this operation!"));

        Session session = this.sessionRepo.findByUserIdAndStatusAndTypeAndExpiryDateAfter(
                user.getId(), SessionStatus.ACTIVE, SessionType.PASSWORD_RESET, Calendar.getInstance().getTime()
                ).orElseThrow(() -> new InvalidOneTimeTokenException("The given token is invalid!"));
        // ensure the rest token matches
        if (!session.getToken().equals(resetToken))
            throw new InvalidOneTimeTokenException("The given token is invalid!");
        // reset the password
        user.setPassword(passwordEncoder.encode(newPassword));
        this.userRepo.save(user);
        session.setStatus(SessionStatus.USED);
        this.sessionRepo.save(session);
    }

    @Override
    public User register(String email, String password, String firstName, String lastName) {
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
    public UserInfoResponse getBasicUserInfo(Long userId) {
        User user = this.userRepo.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        return UserInfoResponse.from(user);
    }
}
