package com.tubebreakup.authorization.model.userToken;

import com.tubebreakup.authorization.model.user.AuthUser;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserTokenResponseDto {

  private AuthUser user;
  private UserToken userToken;
  
  public UserTokenResponseDto(AuthUser user, UserToken userToken) {
    super();
    this.user = user;
    this.userToken = userToken;
  }
}
