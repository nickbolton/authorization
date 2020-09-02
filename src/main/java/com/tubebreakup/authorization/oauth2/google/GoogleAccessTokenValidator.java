package com.tubebreakup.authorization.oauth2.google;

import com.tubebreakup.authorization.model.userToken.UserToken;
import com.tubebreakup.authorization.model.userToken.UserTokenService;
import com.tubebreakup.authorization.model.userToken.UserTokenProvider;
import lombok.Setter;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;

import java.util.Optional;

public class GoogleAccessTokenValidator implements AccessTokenValidator {

  @Setter private UserTokenService userTokenDao;
  @Setter private UserTokenProvider userTokenProvider;

  @Override
  public GoogleTokenPayload validate(String accessToken) {
    Optional<UserToken> optional = userTokenDao.findByToken(accessToken);
    if (!optional.isPresent()) {
      String message = String.format("Missing user token: %s", accessToken);
      throw new UnauthorizedUserException(message);
    }
    UserToken userToken = optional.get();
    if (userToken.isExpired()) {
      String message = String.format("Expired token: %s", accessToken);
      throw new UnauthorizedUserException(message);
    }
    try {
      return userTokenProvider.decodeAuthorizationToken(userToken.getPayload(), null,false, false);
    } catch (Exception e) {
      throw new UnauthorizedUserException("Token not decoded successfully.");
    }
  }
}
