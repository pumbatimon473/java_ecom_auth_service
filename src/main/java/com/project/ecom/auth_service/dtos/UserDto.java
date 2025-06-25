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
    private String firstName;
    private String lastName;
    private String email;
    private List<String> roles;

    public static UserDto from(User user) {
        UserDto userDto = new UserDto();
        userDto.setUserId(user.getId());
        userDto.setFirstName(user.getFirstName());
        userDto.setLastName(user.getLastName());
        userDto.setEmail(user.getEmail());
        if (user.getRoles() != null)
            userDto.setRoles(user.getRoles().stream().map(Role::getName).toList());
        return userDto;
    }
}
