package com.project.ecom.auth_service.controllers;

import com.project.ecom.auth_service.dtos.LoginRequestDto;
import com.project.ecom.auth_service.dtos.SignupRequestDto;
import com.project.ecom.auth_service.dtos.UserDto;
import com.project.ecom.auth_service.models.Session;
import com.project.ecom.auth_service.models.SessionStatus;
import com.project.ecom.auth_service.models.User;
import com.project.ecom.auth_service.services.IAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private IAuthService authService;

    @Autowired
    public AuthController(IAuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/public/signup")
    public ResponseEntity<UserDto> signup(@RequestBody SignupRequestDto requestDto) {
        User user = this.authService.signup(requestDto.getEmail(), requestDto.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(UserDto.from(user));
    }

    @PostMapping("/public/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto requestDto) {
        Session session = this.authService.login(requestDto.getEmail(), requestDto.getPassword());
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, session.getToken());
        headers.add(HttpHeaders.EXPIRES, String.valueOf(session.getExpiryDate().getTime()));
        return ResponseEntity.status(HttpStatus.OK).headers(headers).body(UserDto.from(session.getUser()));
    }
    
    @GetMapping("/logout/{userId}")
    public ResponseEntity<Void> logout(@PathVariable(name = "userId") Long userId, @RequestHeader(name = HttpHeaders.AUTHORIZATION) String accessToken) {
        this.authService.logout(userId, accessToken);
        return ResponseEntity.noContent().build();
    }
    
    @GetMapping("/validate/{userId}")
    public ResponseEntity<String> validate(@PathVariable(name = "userId") Long userId, @RequestHeader HttpHeaders headers) {
        StringBuilder headersInfo = new StringBuilder();
        headers.forEach((key, values) -> {
            headersInfo.append(key).append(": ").append(String.join(", ", values)).append(" | ");
        });
        System.out.println(":: DEBUG :: headers.size() :: " + headers.size());
        System.out.println(":: DEBUG :: validate :: headersInfo :: " + headersInfo.toString());

        SessionStatus sessionStatus = this.authService.validate(userId, headers.getFirst(HttpHeaders.AUTHORIZATION));
        return ResponseEntity.ok(sessionStatus.toString());
    }
}
