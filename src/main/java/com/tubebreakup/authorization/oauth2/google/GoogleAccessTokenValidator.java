package com.tubebreakup.authorization.oauth2.google;

import com.tubebreakup.authorization.model.userToken.UserToken;
import com.tubebreakup.authorization.model.userToken.UserTokenDao;
import com.tubebreakup.authorization.model.userToken.UserTokenProvider;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;

import java.util.Optional;

public class GoogleAccessTokenValidator implements AccessTokenValidator {

  protected Logger logger = LoggerFactory.getLogger(getClass());

  @Setter private UserTokenDao userTokenDao;
  @Setter private UserTokenProvider userTokenProvider;

  @Override
  public GoogleTokenPayload validate(String accessToken) {
    Optional<UserToken> optional = userTokenDao.findByToken(accessToken);
    if (!optional.isPresent()) {
      throw new UnauthorizedUserException("Missing user token.");
    }
    UserToken userToken = optional.get();
    if (userToken.isExpired()) {
      throw new UnauthorizedUserException("Expired token.");
    }
    try {
      return userTokenProvider.decodeAuthorizationToken(userToken.getPayload(), false);
    } catch (Exception e) {
      throw new UnauthorizedUserException("Token not decoded successfully.");
    }
  }
}
