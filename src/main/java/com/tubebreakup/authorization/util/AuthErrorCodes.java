package com.tubebreakup.authorization.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.tubebreakup.exception.ErrorCode;

@JsonSerialize
public enum AuthErrorCodes implements ErrorCode {

    // token requests
    TOKEN_EXPIRED(-9000, "Token expired"),
    BAD_TOKEN(-9001, "Bad token"),
    NO_TOKEN(-9002, "No token"),
    INVALID_TOKEN(-9003, "Invalid token"),
    ;

    @JsonProperty
    private Integer value;

    @JsonProperty
    private String message;

    private AuthErrorCodes(final Integer value, final String message) {
        this.value = value;
        this.message = message;
    }

    public Integer value() { return value; }
    public String message() { return message; }
}
