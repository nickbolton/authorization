package com.tubebreakup.authorization.util;

import com.tubebreakup.authorization.oauth2.AuthorizationTokenType;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class RefreshTokenProviderResolver implements InitializingBean {

    @Autowired
    private DefaultRefreshTokenProvider defaultRefreshTokenProvider;

    @Autowired
    private GoogleRefreshTokenProvider googleRefreshTokenProvider;

    @Autowired
    private AuthorizationTokenTypeResolver authorizationTokenTypeResolver;

    private Map<AuthorizationTokenType, RefreshTokenProvider> refreshProviders = new HashMap<>();

    @Override
    public void afterPropertiesSet() throws Exception {
        refreshProviders.put(AuthorizationTokenType.DEFAULT, defaultRefreshTokenProvider);
        refreshProviders.put(AuthorizationTokenType.GOOGLE, googleRefreshTokenProvider);
    }

    public RefreshTokenProviderWrapper getRefreshTokenProvider(String refreshToken) {
        if (refreshToken == null) {
            return null;
        }
        AuthorizationTokenWrapper tokenWrapper = authorizationTokenTypeResolver.resolveAuthorizationTokenType(refreshToken);
        if (tokenWrapper == null) {
            return null;
        }
        if (tokenWrapper.getType() != null) {
            RefreshTokenProvider provider = refreshProviders.get(tokenWrapper.getType());
            if (provider != null) {
                return new RefreshTokenProviderWrapper(provider, tokenWrapper.getToken());
            }
        }
        return null;
    }
}