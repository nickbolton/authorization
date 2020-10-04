package com.tubebreakup.authorization.model.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Set;

@JsonSerialize
public enum AuthUserRole {
    ROLE_SYSTEM(0),
    ROLE_USER(1),
    ROLE_ADMIN(2),
    ;

    @JsonProperty
    private Integer value;

    AuthUserRole(final Integer value) {
        this.value = value;
    }

    public Integer value() {
        return value;
    }

    public Boolean userHasRole(AuthUser user) {
        if (user == null) {
            return false;
        }
        Set<AuthUserRole> roles = user.getRoles();
        return roles != null && roles.contains(this);
    }
}
