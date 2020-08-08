package com.tubebreakup.authorization.util;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class UniqueTokenProvider {

  public String buildUniqueToken() {
    return UUID.randomUUID().toString();
  }
}
