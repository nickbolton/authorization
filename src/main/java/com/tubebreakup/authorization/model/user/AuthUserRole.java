package com.tubebreakup.authorization.model.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

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
}
