package com.project.ecom.auth_service.security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.project.ecom.auth_service.models.User;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/* Issues: Encountered after enabling persistent registered client repository

On trying to get the oauth token through postman: Password matches but authentication failed
Query: Why the same issues were not encountered when using an in-memory registered client?

1) The class with name of CustomUserDetails is not in the allowlist.
If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations
or by providing a Mixin. If the serialization is only done by a trusted source,
you can also enable default typing. See https://github.com/spring-projects/spring-security/issues/4370 for details

Solution: Use @JsonDeserialize to add the class in the allowlist.

2) Cannot construct instance of `CustomUserDetails` (no Creators, like default constructor, exist):
cannot deserialize from Object value (no delegate- or property-based Creator)

Solution: Create a default CTOR - @NoArgsConstructor

3) Unrecognized field "enabled" (class CustomUserDetails), not marked as ignorable (one known property: "authorities"])

Cause: The Jackson2Json object mapper expects an associated field for every getter (also includes a method starting with 'is')
- Currently there is only one field 'user'

Solution: Create a field for every getter

4) The class with name of java.util.ImmutableCollections$ListN is not in the allowlist.
If you believe this class is safe to deserialize, please provide an explicit mapping using Jackson annotations or by providing a Mixin.

Cause: CustomGrantedAuthority is not in the allowlist.

Solution: Repeat the same process for CustomGrantedAuthority
 */

@JsonDeserialize
@NoArgsConstructor
public class CustomUserDetails implements UserDetails {
    // private User user;
    @Getter
    private Long userId;
    private List<? extends GrantedAuthority> authorities;
    private String password;
    private String username;
    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private Boolean credentialsNonExpired;
    private Boolean enabled;

    public CustomUserDetails(User user) {
        this.userId = user.getId();
        this.username = user.getEmail();
        this.password = user.getPassword();  // ** note: user password is stored in encoded form
        // what we call a user's Role, spring security is calling it a GrantedAuthority
        // this.authorities = user.getRoles().parallelStream().map(CustomGrantedAuthority::new).toList();  // returns an immutable list; unable to deserialize
        this.authorities = user.getRoles().parallelStream().map(CustomGrantedAuthority::new).collect(Collectors.toList());  // mutable list
        this.accountNonExpired = true;  // user account never expires
        this.accountNonLocked = true;  // user account cannot be locked
        this.credentialsNonExpired = true;  // password never expires
        this.enabled = true;  // user is always active
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

}
