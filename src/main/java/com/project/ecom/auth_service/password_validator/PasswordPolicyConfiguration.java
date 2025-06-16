package com.project.ecom.auth_service.password_validator;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.password-policy")
@Getter
@Setter
public class PasswordPolicyConfiguration {
    private Integer minLen;
    private Integer maxLen;
    private Boolean lowercaseRequired;
    private Boolean uppercaseRequired;
    private Boolean specialCharRequired;
    private Boolean digitRequired;
}
