package com.tubebreakup.authorization.model.userToken;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize
public enum UserTokenType {
  REGISTRATION(0), 
  INVITATION(1), 
  PASSWORD_RESET(2),
  CHANGE_EMAIL(3),
  AUTHORIZATION(4),
  OAUTH2(5),
  ;

  @JsonProperty
  private Integer value;

  UserTokenType(final Integer value) {
    this.value = value; 
  }

  public Integer value() {
    return value;
  }
}
