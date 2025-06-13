package com.project.ecom.auth_service.controllers;

import com.project.ecom.auth_service.dtos.CreateRoleRequestDto;
import com.project.ecom.auth_service.dtos.CreateRoleResponseDto;
import com.project.ecom.auth_service.dtos.SetRolesToUserReqDto;
import com.project.ecom.auth_service.models.Role;
import com.project.ecom.auth_service.services.IRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/role")
public class RoleController {
    private IRoleService roleService;

    @Autowired
    public RoleController(IRoleService roleService) {
        this.roleService = roleService;
    }

    @PostMapping
    ResponseEntity<CreateRoleResponseDto> createNewRole(@RequestBody CreateRoleRequestDto requestDto) {
        Role role = this.roleService.createNewRole(requestDto.getRoleName());
        return ResponseEntity.status(HttpStatus.CREATED).body(CreateRoleResponseDto.from(role));
    }

    @PostMapping("/assign")
    ResponseEntity<Void> setRolesToUser(@RequestBody SetRolesToUserReqDto requestDto) {
        this.roleService.setRolesToUser(requestDto.getRoleNames(), requestDto.getUserId());
        return ResponseEntity.noContent().build();
    }
}
