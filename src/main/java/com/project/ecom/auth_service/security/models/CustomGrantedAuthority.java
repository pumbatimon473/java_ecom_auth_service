package com.project.ecom.auth_service.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.project.ecom.auth_service.models.Role;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

/* Issues: Encountered after enabling persistent registered client repository

On trying to get the oauth token through postman: Password matches but authentication failed

1) CustomGrantedAuthority is not safe to deserialize.
- For details refer CustomUserDetails

Cause: Spring security blocks any class, which is not in its allowlist for deserialization.

Solution: Use @JsonDeserialize to add the class in the allowlist.
- Associated nuances:
    - requires a default CTOR
    - requires a field for every getter (also includes methods starting with 'is')
 */

@JsonDeserialize
@NoArgsConstructor
public class CustomGrantedAuthority implements GrantedAuthority {
    // private Role role;
    private String authority;

    public CustomGrantedAuthority(Role role) {
        this.authority = "ROLE_" + role.getName();  // prefixed with ROLE_ (expected by spring)
    }

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
