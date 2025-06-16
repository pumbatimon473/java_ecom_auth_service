package com.project.ecom.auth_service;

import com.project.ecom.auth_service.password_validator.PasswordPolicyConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(PasswordPolicyConfiguration.class)
public class JavaEcomAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(JavaEcomAuthServiceApplication.class, args);
    }

}
