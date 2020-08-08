package com.tubebreakup.authorization.oauth2;

import lombok.Setter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

public class TokenServices implements ResourceServerTokenServices {

  private ResourceServerTokenServices defaultTokenServices;

  @Setter private TokenStore tokenStore;

  @Setter private ClientDetailsService clientDetailsService;
  
  private ResourceServerTokenServices getDefaultTokenServices() {
    if (defaultTokenServices == null) {
      defaultTokenServices = createDefaultTokenServices();
    }
    return defaultTokenServices;
  }

  private DefaultTokenServices createDefaultTokenServices() {
    DefaultTokenServices tokenServices = new DefaultTokenServices();
    tokenServices.setTokenStore(tokenStore);
    tokenServices.setSupportRefreshToken(true);
    tokenServices.setReuseRefreshToken(true);
    tokenServices.setClientDetailsService(clientDetailsService);
    tokenServices.setTokenEnhancer(null);
    return tokenServices;
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessToken)
      throws AuthenticationException, InvalidTokenException {
    return getDefaultTokenServices().loadAuthentication(accessToken);    
  }

  @Override
  public OAuth2AccessToken readAccessToken(String accessToken) {
    return getDefaultTokenServices().readAccessToken(accessToken);
  }

  public TokenServices(TokenStore tokenStore, ClientDetailsService clientDetailsService) {
    super();
    this.tokenStore = tokenStore;
    this.clientDetailsService = clientDetailsService;
  }
}
