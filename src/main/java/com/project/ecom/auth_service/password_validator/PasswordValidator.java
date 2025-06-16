package com.project.ecom.auth_service.password_validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/* Read More:
https://dzone.com/articles/spring-boot-custom-password-validator-using-passay
https://www.passay.org/reference/
 */

@Component
public class PasswordValidator implements ConstraintValidator<ValidPassword, String> {
    private final PasswordPolicyConfiguration passwordPolicy;

    @Autowired
    public PasswordValidator(PasswordPolicyConfiguration passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    @Override
    public boolean isValid(String rawPassword, ConstraintValidatorContext constraintValidatorContext) {
        if (rawPassword == null)
            return false;
        if (rawPassword.length() < passwordPolicy.getMinLen() || rawPassword.length() > passwordPolicy.getMaxLen())
            return false;
        if (passwordPolicy.getLowercaseRequired() && !rawPassword.matches(".*[a-z].*"))
            return false;
        if (passwordPolicy.getUppercaseRequired() && !rawPassword.matches(".*[A-Z].*"))
            return false;
        if (passwordPolicy.getSpecialCharRequired() && !rawPassword.matches(".*[^\\da-zA-Z].*"))
            return false;
        if (passwordPolicy.getDigitRequired() && !rawPassword.matches(".*\\d.*"))
            return false;

        return true;
    }
}
