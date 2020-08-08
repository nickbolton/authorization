package com.tubebreakup.authorization.util;

import com.tubebreakup.authorization.oauth2.AuthorizationTokenType;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class AuthorizationTokenTypeResolver implements InitializingBean {
  
  @Value("${com.tubebreakup.authorization_token_prefix.DEFAULT}")
  protected String defaultAuthorizationTokenPrefix;

  @Value("${com.tubebreakup.authorization_token_prefix.GOOGLE}")
  protected String googleAuthorizationTokenPrefix;

  @Value("${com.tubebreakup.authorization_token_prefix.USER_TOKEN}")
  protected String userTokenAuthorizationTokenPrefix;

  private Map<AuthorizationTokenType, String> prefixMap = new HashMap<>();

  @Override
  public void afterPropertiesSet() throws Exception {
    prefixMap.put(AuthorizationTokenType.DEFAULT, defaultAuthorizationTokenPrefix);
    prefixMap.put(AuthorizationTokenType.GOOGLE, googleAuthorizationTokenPrefix);
    prefixMap.put(AuthorizationTokenType.USER_TOKEN, userTokenAuthorizationTokenPrefix);
  }
  
  public String prefixForTokenType(AuthorizationTokenType type) {
    if (!prefixMap.containsKey(type)) {
      throw new IllegalArgumentException(String.format("token type not mapped! %s" , type.name()));
    }
    return prefixMap.get(type);
  }

  public String namespaceToken(String token, AuthorizationTokenType type) {
    String prefix = prefixForTokenType(type);
    if (token == null || token.startsWith(prefix)) {
      return token;
    }
    return new StringBuilder(prefix).append(token).toString();
  }

  public AuthorizationTokenWrapper resolveAuthorizationTokenType(String token) {
    for (AuthorizationTokenType type: prefixMap.keySet()) {
      String prefix = prefixForTokenType(type);
      if (token.startsWith(prefix)) {
        String resolvedToken = "";
        if (token.length() > prefix.length()) {
          resolvedToken = token.substring(prefix.length());
        }
        return new AuthorizationTokenWrapper(type, resolvedToken);
      }
    }
    return null;
  }
}
