package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.models.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateRoleResponseDto {
    private Long id;
    private String role;

    public static CreateRoleResponseDto from(Role role) {
        CreateRoleResponseDto responseDto = new CreateRoleResponseDto();
        responseDto.setId(role.getId());
        responseDto.setRole(role.getName());
        return responseDto;
    }
}
