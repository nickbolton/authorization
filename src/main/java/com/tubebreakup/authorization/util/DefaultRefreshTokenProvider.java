package com.tubebreakup.authorization.util;

import com.tubebreakup.authorization.model.AccessTokenResponseDto;
import com.tubebreakup.authorization.oauth2.AuthorizationTokenType;
import com.tubebreakup.exception.CommonErrors;
import com.tubebreakup.exception.ErrorCodedHttpException;
import com.tubebreakup.util.HttpErrorHandler;
import com.tubebreakup.util.HttpErrorResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Map;

@Component
public class DefaultRefreshTokenProvider implements RefreshTokenProvider {

  @Value("${oauth2.client.id}")
  protected String oauth2ClientID;

  @Value("${oauth2.client.secret}")
  protected String oauth2ClientSecret;
  
  @Autowired
  protected AuthorizationTokenTypeResolver authorizationTokenTypeResolver;

  @Autowired
  private HttpErrorHandler httpErrorHandler;

  @Value("${server.port}")
  private String serverPort;

  @SuppressWarnings("rawtypes")
  @Override
  public AccessTokenResponseDto refreshAccessToken(String refreshToken) {
    RestTemplate restTemplate = new RestTemplate();

    String authURI = ServletUriComponentsBuilder.fromHttpUrl("http://localhost:"+serverPort).path("/oauth/token").toUriString();

    String auth = oauth2ClientID + ":" + oauth2ClientSecret;
    byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(Charset.forName("US-ASCII")));
    String authHeader = "Basic " + new String(encodedAuth);

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    headers.set(HttpHeaders.AUTHORIZATION, authHeader);

    HttpEntity<String> entity = new HttpEntity<>("refresh_token="+refreshToken+"&grant_type=refresh_token", headers);
    ResponseEntity<Map> result;

    try {
      result = restTemplate.postForEntity(authURI, entity, Map.class);
    } catch (HttpClientErrorException e) {
      HttpErrorResponse errorResponse = httpErrorHandler.parseErrorResponse(e);
      if (errorResponse != null) {
        throw new ErrorCodedHttpException(HttpStatus.BAD_REQUEST, CommonErrors.INVALID_REQUEST, errorResponse.getErrorDescription());
      }
      throw new ErrorCodedHttpException(HttpStatus.BAD_REQUEST, CommonErrors.INVALID_REQUEST);
    }

    String accessToken = (String) result.getBody().get("access_token");
    String tokenType = (String) result.getBody().get("token_type");
    String scope = (String) result.getBody().get("scope");
    Long expiresIn = ((Integer) result.getBody().get("expires_in")).longValue();

    String namespacedAccessToken = authorizationTokenTypeResolver.namespaceToken(accessToken, AuthorizationTokenType.DEFAULT);
    String namespacedRefreshToken = authorizationTokenTypeResolver.namespaceToken(refreshToken, AuthorizationTokenType.DEFAULT);

    return new AccessTokenResponseDto(namespacedAccessToken, tokenType, namespacedRefreshToken, expiresIn, scope, null, null);
  }
}
