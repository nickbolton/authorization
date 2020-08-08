package com.tubebreakup.authorization.oauth2.google;

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

public class GoogleTokenServices implements ResourceServerTokenServices {

  private AccessTokenValidator tokenValidator;

  public GoogleTokenServices(AccessTokenValidator tokenValidator) {
    this.tokenValidator = tokenValidator;
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessToken)
      throws AuthenticationException, InvalidTokenException {
    GoogleTokenPayload validationResult = tokenValidator.validate(accessToken);
    OAuth2Authentication authentication = getAuthentication(validationResult, accessToken);
    return authentication;    
  }

  private OAuth2Authentication getAuthentication(GoogleTokenPayload result, String accessToken) {
    OAuth2Request request = new OAuth2Request(null, result.getClientId(), null, true, null, null, null, null, null);
    
    Authentication authentication = new UsernamePasswordAuthenticationToken(result.getUserId(), null, singleton(new SimpleGrantedAuthority("ROLE_USER")));
    return new OAuth2Authentication(request, authentication);
  }

  @Override
  public OAuth2AccessToken readAccessToken(String accessToken) {
    throw new UnsupportedOperationException("Not supported: read access token");
  }
}
