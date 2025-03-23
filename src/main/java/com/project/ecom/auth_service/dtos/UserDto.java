package com.project.ecom.auth_service.dtos;

import com.project.ecom.auth_service.models.Role;
import com.project.ecom.auth_service.models.User;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class UserDto {
    private Long userId;
    private String email;
    private List<Role> roles;

    public static UserDto from(User user) {
        UserDto userDto = new UserDto();
        userDto.setUserId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setRoles(user.getRoles());
        return userDto;
    }
}
