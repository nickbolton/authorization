package com.tubebreakup.authorization.oauth2.google;

public interface AccessTokenValidator {
    public GoogleTokenPayload validate(String accessToken);
}
