package com.tubebreakup.authorization.oauth2;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize
public enum AuthorizationTokenType {
  DEFAULT(0),
  GOOGLE(1),
  USER_TOKEN(2),
  ;

  @JsonProperty
  private Integer value;

  AuthorizationTokenType(final Integer value) {
    this.value = value; 
  }

  public Integer value() {
    return value;
  }
  
  public String stringValue() {
    try {
      return new ObjectMapper().writeValueAsString(this);
    } catch (JsonProcessingException e) {
      return "UNKNOWN";
    }
  }
}
