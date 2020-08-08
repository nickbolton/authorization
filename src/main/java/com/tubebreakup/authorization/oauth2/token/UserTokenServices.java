package com.tubebreakup.authorization.oauth2.token;

import com.tubebreakup.authorization.model.userToken.JWTTokenPayload;
import com.tubebreakup.authorization.model.userToken.UserTokenProvider;
import com.tubebreakup.exception.ErrorCodedHttpException;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import static java.util.Collections.singleton;

public class UserTokenServices implements ResourceServerTokenServices, InitializingBean {

    @Setter private UserTokenProvider userTokenProvider;

    @Value("#{applicationProperties['com.tubebreakup.authorization_token_prefix.USER_TOKEN'].replace(\"|\", \"\")}")
    protected String clientId;

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {

        JWTTokenPayload payload;
        try {
            payload = userTokenProvider.decodeAuthorizationToken(accessToken, false);
        } catch (ErrorCodedHttpException e) {
            throw new InvalidTokenException(e.getMessage(), e);
        }

        OAuth2Request request = new OAuth2Request(null, clientId, null, true, null, null, null, null, null);

        Authentication authentication = new UsernamePasswordAuthenticationToken(payload.getRecipientEmail(), null, singleton(new SimpleGrantedAuthority("USER_TOKEN")));
        return new OAuth2Authentication(request, authentication);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    @Override
    public void afterPropertiesSet() throws Exception {

    }
}
