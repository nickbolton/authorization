package com.tubebreakup.authorization.oauth2;

import com.tubebreakup.authorization.util.AuthorizationTokenTypeResolver;
import com.tubebreakup.authorization.util.AuthorizationTokenWrapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.HashMap;
import java.util.Map;

public class TokenServicesAdapter implements ResourceServerTokenServices {
  
  @AllArgsConstructor
  private class ResourceServiceWrapper {
    @Getter ResourceServerTokenServices tokenServices;
    @Getter String accessToken;
  }
  
  private Map<AuthorizationTokenType, ResourceServerTokenServices> registeredServices = new HashMap<>();
  private AuthorizationTokenTypeResolver remoteTokenTypeResolver;
  
  public TokenServicesAdapter(AuthorizationTokenTypeResolver remoteTokenTypeResolver) {
    super();
    this.remoteTokenTypeResolver = remoteTokenTypeResolver;
  }
  
  public void registerTokenService(AuthorizationTokenType type, ResourceServerTokenServices service) {
    registeredServices.put(type, service);
  }

  private ResourceServiceWrapper getTokenServices(String accessToken) {
    if (accessToken == null) {
      return null;
    }
    AuthorizationTokenWrapper tokenWrapper = remoteTokenTypeResolver.resolveAuthorizationTokenType(accessToken);
    if (tokenWrapper == null) {
      return null;
    }
    if (tokenWrapper.getType() != null) {
      ResourceServerTokenServices service = registeredServices.get(tokenWrapper.getType());
      if (service != null) {
        return new ResourceServiceWrapper(service, tokenWrapper.getToken());
      }
    }
    return null;    
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessToken)
      throws AuthenticationException, InvalidTokenException {
    ResourceServiceWrapper wrapper = getTokenServices(accessToken);
    if (wrapper == null) {
      return null;
    }
    return wrapper.getTokenServices().loadAuthentication(wrapper.getAccessToken());
  }

  @Override
  public OAuth2AccessToken readAccessToken(String accessToken) {
    ResourceServiceWrapper wrapper = getTokenServices(accessToken);
    if (wrapper == null) {
      return null;
    }
    return wrapper.getTokenServices().readAccessToken(wrapper.getAccessToken());
  }
}
