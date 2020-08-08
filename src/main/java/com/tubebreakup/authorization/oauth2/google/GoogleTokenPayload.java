package com.tubebreakup.authorization.oauth2.google;

import com.tubebreakup.authorization.model.userToken.JWTTokenPayload;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleTokenPayload extends JWTTokenPayload {
    private String clientId;
    private String accessToken;
    private String refreshToken;
    private String userId;
    private String email;
    private Boolean emailVerified;
}
