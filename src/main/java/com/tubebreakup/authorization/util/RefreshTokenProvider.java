package com.tubebreakup.authorization.util;

import com.tubebreakup.authorization.model.AccessTokenResponseDto;

public interface RefreshTokenProvider {
  public AccessTokenResponseDto refreshAccessToken(String refreshToken);
}
