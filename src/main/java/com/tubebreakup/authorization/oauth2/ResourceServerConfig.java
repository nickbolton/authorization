package com.tubebreakup.authorization.oauth2;

import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.tubebreakup.authorization.model.userToken.UserTokenDao;
import com.tubebreakup.authorization.model.userToken.UserTokenProvider;
import com.tubebreakup.authorization.oauth2.google.AccessTokenValidator;
import com.tubebreakup.authorization.oauth2.google.GoogleAccessTokenValidator;
import com.tubebreakup.authorization.oauth2.google.GoogleTokenServices;
import com.tubebreakup.authorization.oauth2.token.UserTokenServices;
import com.tubebreakup.authorization.util.AuthorizationTokenTypeResolver;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter implements InitializingBean {

    @Autowired
    private UserTokenDao userTokenDao;

    private GoogleTokenServices googleTokenServices;

    @Autowired
    private UserTokenProvider userTokenProvider;

    private UserTokenServices userTokenServices;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private GoogleClientSecrets.Details googleClientDetails;

    @Autowired
    private AuthorizationTokenTypeResolver authorizationTokenTypeResolver;

    @Override
    public void afterPropertiesSet() throws Exception {
        if (userTokenServices != null) {
            userTokenServices.setUserTokenProvider(userTokenProvider);
        }
    }

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http.
        anonymous().disable()
        .authorizeRequests()
        .antMatchers("/users/**").access("hasRole('USER')")
        .antMatchers("/system/**").access("hasRole('SYSTEM')")
        .antMatchers("/token/**").access("hasRole('USER_TOKEN')")
        .and().exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler());
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(googleClientDetails.getClientId()).stateless(false);
    }

    @Bean
    public ResourceServerTokenServices tokenServices(AccessTokenValidator tokenValidator) {

        userTokenServices = new UserTokenServices();
        userTokenServices.setUserTokenProvider(userTokenProvider);

        googleTokenServices = new GoogleTokenServices(tokenValidator);

        TokenServicesAdapter result = new TokenServicesAdapter(authorizationTokenTypeResolver);
        result.registerTokenService(AuthorizationTokenType.DEFAULT, new TokenServices(tokenStore, clientDetailsService));
        result.registerTokenService(AuthorizationTokenType.GOOGLE, googleTokenServices);
        result.registerTokenService(AuthorizationTokenType.USER_TOKEN, userTokenServices);

        return result;
    }

    @Bean
    public GoogleAccessTokenValidator googleTokenValidator() {
        GoogleAccessTokenValidator accessTokenValidator = new GoogleAccessTokenValidator();
        accessTokenValidator.setUserTokenDao(userTokenDao);
        accessTokenValidator.setUserTokenProvider(userTokenProvider);
        return accessTokenValidator;
    }
}
