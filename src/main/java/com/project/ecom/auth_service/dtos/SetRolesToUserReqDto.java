package com.project.ecom.auth_service.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class SetRolesToUserReqDto {
    private List<String> roleNames;
    private Long userId;
}
