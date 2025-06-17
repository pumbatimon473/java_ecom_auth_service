package com.project.ecom.auth_service.controllers;

import com.project.ecom.auth_service.dtos.*;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.services.IUserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final IUserService userService;

    public UserController(IUserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@Valid @RequestBody SignupRequestDto requestDto) {
        User user = this.userService.register(requestDto.getEmail(), requestDto.getPassword(), requestDto.getFirstName(), requestDto.getLastName());
        return ResponseEntity.status(HttpStatus.CREATED).body(UserDto.from(user));
    }

    @PostMapping("/login")
    public ResponseEntity<AccessTokenResponse> login(@Valid @RequestBody LoginRequestDto requestDto) {
        AccessTokenResponse accessTokenResponse = this.userService.login(requestDto.getEmail(), requestDto.getPassword());
        return ResponseEntity.ok(accessTokenResponse);
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@Valid @RequestBody ChangePasswordRequestDto requestDto, Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String email = jwt.getSubject();
        this.userService.changePassword(email, requestDto.getOldPassword(), requestDto.getNewPassword());
        return ResponseEntity.ok("Password has been changed.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetRequestDto requestDto) throws ParseException {
        this.userService.resetPassword(requestDto.getEmail());
        return ResponseEntity.ok("Password reset link has been sent to the registered email id.");
    }

    @PostMapping("/reset-password/confirm")
    public ResponseEntity<String> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequestDto requestDto) throws ParseException {
        this.userService.confirmPasswordReset(requestDto.getNewPassword(), requestDto.getResetToken());
        return ResponseEntity.ok("Password has been reset!");
    }

    @GetMapping("/basic-info/{id}")
    public ResponseEntity<UserInfoResponse> getBasicUserInfo(@PathVariable(name = "id") Long userId) {
        UserInfoResponse userInfoResponse = this.userService.getBasicUserInfo(userId);
        return ResponseEntity.ok(userInfoResponse);
    }
}
