package com.tubebreakup.authorization.model;

import com.tubebreakup.authorization.model.user.AuthUser;
import com.tubebreakup.authorization.model.userToken.UserToken;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessTokenResponseDto {

  private String access_token;
  private String token_type;
  private String refresh_token;
  private Long expires_in;
  private String scope;
  private AuthUser user;
  private UserToken userToken;
  
  public AccessTokenResponseDto(String access_token, String token_type, String refresh_token, Long expires_in,
                                String scope, AuthUser user, UserToken userToken) {
    super();
    this.access_token = access_token;
    this.token_type = token_type;
    this.refresh_token = refresh_token;
    this.expires_in = expires_in;
    this.scope = scope;
    this.user = user;
    this.userToken = userToken;
  }
  
  protected AccessTokenResponseDto() {
    super();
  }
}
