package com.tubebreakup.authorization.util;

import com.tubebreakup.authorization.oauth2.AuthorizationTokenType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class AuthorizationTokenWrapper {
  @Getter private AuthorizationTokenType type;
  @Getter private String token;
}
