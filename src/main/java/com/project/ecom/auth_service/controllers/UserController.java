package com.project.ecom.auth_service.controllers;

import com.project.ecom.auth_service.dtos.AccessTokenResponse;
import com.project.ecom.auth_service.dtos.LoginRequestDto;
import com.project.ecom.auth_service.services.IUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final IUserService userService;

    public UserController(IUserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<AccessTokenResponse> login(@RequestBody LoginRequestDto requestDto) {
        AccessTokenResponse accessTokenResponse = this.userService.login(requestDto.getEmail(), requestDto.getPassword());
        return ResponseEntity.ok(accessTokenResponse);
    }
}
