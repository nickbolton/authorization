package com.tubebreakup.authorization.oauth2;

import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.tubebreakup.exception.CommonErrors;
import com.tubebreakup.exception.ErrorCodedHttpException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.io.InputStreamReader;

@Configuration
public class GoogleOAuth2Config {

  @Autowired
  private ResourceLoader resourceLoader;
  
  @Bean
  public GoogleClientSecrets.Details getDetails() {
    final String secretPath = "classpath:google-client-details.json";

    // Exchange auth code for access token
    GoogleClientSecrets clientSecrets;
    Resource resource = resourceLoader.getResource(secretPath);
    if (!resource.exists()) {
      throw new ErrorCodedHttpException(HttpStatus.INTERNAL_SERVER_ERROR, CommonErrors.SERVER_ERROR, "Couldn't find google config");
    }
    try {
      clientSecrets = GoogleClientSecrets.load(JacksonFactory.getDefaultInstance(), new InputStreamReader(resource.getInputStream()));
    } catch (IOException e) {
      throw new ErrorCodedHttpException(HttpStatus.INTERNAL_SERVER_ERROR, CommonErrors.SERVER_ERROR, "Couldn't load google config", e);
    }
    
    return clientSecrets.getDetails();
  }
}
