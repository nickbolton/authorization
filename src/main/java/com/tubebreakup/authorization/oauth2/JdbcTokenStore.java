package com.tubebreakup.authorization.oauth2;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import javax.sql.DataSource;
import java.sql.Types;
import java.util.Date;

public class JdbcTokenStore extends org.springframework.security.oauth2.provider.token.store.JdbcTokenStore {

  private final JdbcTemplate myJdbcTemplate;
  private AuthenticationKeyGenerator myAuthenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

  public JdbcTokenStore(DataSource dataSource) {
    super(dataSource);
    this.myJdbcTemplate = new JdbcTemplate(dataSource);
  }

  @Override
  public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
    super.setAuthenticationKeyGenerator(authenticationKeyGenerator);
    this.myAuthenticationKeyGenerator = authenticationKeyGenerator;
  }

  @Override
  public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
    
    final String sql = "insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token, expiration) values (?, ?, ?, ?, ?, ?, ?, ?)";

    String refreshToken = null;
    if (token.getRefreshToken() != null) {
      refreshToken = token.getRefreshToken().getValue();
    }
    
    if (readAccessToken(token.getValue())!=null) {
      removeAccessToken(token.getValue());
    }

    myJdbcTemplate.update(sql, new Object[] { extractTokenKey(token.getValue()),
        new SqlLobValue(serializeAccessToken(token)), myAuthenticationKeyGenerator.extractKey(authentication),
        authentication.isClientOnly() ? null : authentication.getName(),
        authentication.getOAuth2Request().getClientId(),
        new SqlLobValue(serializeAuthentication(authentication)), extractTokenKey(refreshToken), token.getExpiration() }, new int[] {
        Types.VARCHAR, Types.BLOB, Types.VARCHAR, Types.VARCHAR, Types.VARCHAR, Types.BLOB, Types.VARCHAR, Types.TIMESTAMP });
  }

  @Override
  public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
    
    final String sql = "insert into oauth_refresh_token (token_id, token, authentication, expiration) values (?, ?, ?, ?)";
    
    Date expiration = null;
    
    if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
      expiration = ((ExpiringOAuth2RefreshToken)refreshToken).getExpiration();
    }

    myJdbcTemplate.update(sql, new Object[] { extractTokenKey(refreshToken.getValue()),
        new SqlLobValue(serializeRefreshToken(refreshToken)),
        new SqlLobValue(serializeAuthentication(authentication)),
        expiration }, new int[] { Types.VARCHAR, Types.BLOB,
        Types.BLOB, Types.TIMESTAMP });
  }
}
