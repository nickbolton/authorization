package com.tubebreakup.authorization.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.tubebreakup.authorization.model.AccessTokenResponseDto;
import com.tubebreakup.authorization.model.userToken.UserToken;
import com.tubebreakup.authorization.model.userToken.UserTokenProvider;
import com.tubebreakup.authorization.model.userToken.UserTokenRepository;
import com.tubebreakup.authorization.oauth2.AuthorizationTokenType;
import com.tubebreakup.authorization.oauth2.google.GoogleTokenPayload;
import com.tubebreakup.exception.CommonErrors;
import com.tubebreakup.exception.ErrorCodedHttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

@Component
public class GoogleRefreshTokenProvider implements RefreshTokenProvider {

  protected Logger logger = LoggerFactory.getLogger(getClass());

  @Autowired
  private GoogleClientSecrets.Details googleClientDetails;

  @Autowired
  private AuthorizationTokenTypeResolver authorizationTokenTypeResolver;

  @Autowired
  private UserTokenProvider userTokenProvider;

  @Autowired
  private UserTokenRepository userTokenRepository;

  private RestTemplate restTemplate = new RestTemplate();
  
  @SuppressWarnings("rawtypes")
  @Override
  public AccessTokenResponseDto refreshAccessToken(String refreshToken) {
    try {
      Optional<UserToken> userTokenOptional = userTokenRepository.findByRefreshToken(refreshToken);
      if (!userTokenOptional.isPresent()) {
        throw new ErrorCodedHttpException(
                HttpStatus.UNAUTHORIZED,
                CommonErrors.RESOURCE_NOT_FOUND,
                String.format("No user token found for refreshToken: %s", refreshToken)
        );
      }

      ResponseEntity<Map> result = sendRefreshRequest(refreshToken);

      String accessToken = (String) result.getBody().get("access_token");
      String tokenType = (String) result.getBody().get("token_type");
      String scope = (String) result.getBody().get("scope");
      Long expirationInMinutes = ((Integer) result.getBody().get("expires_in")).longValue();
      
      String namespacedAccessToken = authorizationTokenTypeResolver.namespaceToken(accessToken, AuthorizationTokenType.GOOGLE);
      String namespacedRefreshToken = authorizationTokenTypeResolver.namespaceToken(refreshToken, AuthorizationTokenType.GOOGLE);

      UserToken userToken = userTokenOptional.get();
      GoogleTokenPayload tokenPayload = userTokenProvider.decodeAuthorizationToken(userToken.getPayload(), null, false);
      tokenPayload.setAccessToken(accessToken);

      try {
        userTokenProvider.updateOAuth2Token(
                userToken,
                userToken.getEmail(),
                accessToken,
                refreshToken,
                expirationInMinutes.intValue(),
                tokenPayload
        );
      } catch (JsonProcessingException e) {
        throw new ErrorCodedHttpException(HttpStatus.INTERNAL_SERVER_ERROR, CommonErrors.RESOURCE_SERVER_EXCHANGE_FAILED, e);
      }

      return new AccessTokenResponseDto(
              namespacedAccessToken,
              tokenType,
              namespacedRefreshToken,
              expirationInMinutes,
              scope,
              null,
              null
      );
    } catch (HttpClientErrorException e) {
      throw new ErrorCodedHttpException(HttpStatus.UNAUTHORIZED, CommonErrors.BAD_CREDENTIALS);
    }
  }

  private ResponseEntity<Map> sendRefreshRequest(String refreshToken) {
    final String url = "https://oauth2.googleapis.com/token";

    MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<String, String>();
    bodyMap.add("client_id", googleClientDetails.getClientId());
    bodyMap.add("client_secret", googleClientDetails.getClientSecret());
    bodyMap.add("refresh_token", refreshToken);
    bodyMap.add("grant_type", "refresh_token");

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(bodyMap, headers);
    try {
      return restTemplate.postForEntity(url, entity, Map.class);
    } catch (RestClientException e) {
      String message = "Failed refreshing google token";
      logger.error(message, e);
      throw new ErrorCodedHttpException(HttpStatus.UNAUTHORIZED, AuthErrorCodes.BAD_TOKEN, message);
    }
  }
}
