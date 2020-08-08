package com.tubebreakup.authorization.model.userToken;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JWTTokenPayload {
    private String recipientEmail;
    private String userTokenId;
    private String tokenType;

    public JWTTokenPayload() {
        super();
        setTokenType(getClass().getName());
    }
}
