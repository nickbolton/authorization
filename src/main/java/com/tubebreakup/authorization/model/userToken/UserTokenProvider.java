package com.tubebreakup.authorization.model.userToken;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tubebreakup.authorization.util.AuthErrorCodes;
import com.tubebreakup.authorization.util.UniqueTokenProvider;
import com.tubebreakup.exception.ErrorCodedHttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Date;
import java.util.Optional;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

@Service
public class UserTokenProvider {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${token.auth.prefix}")
    private String bearerPrefix;

    @Value("${token.secret}")
    private String secret;

    @Value("${com.tubebreakup.authorization_token_prefix.USER_TOKEN}")
    private String authorizationPrefix;

    @Autowired
    private UniqueTokenProvider tokenProvider;

    @Autowired
    private UserTokenDao userTokenDao;

    public UserToken fetchUserToken(String email, UserTokenType tokenType) {
        UserToken userToken;
        String token = tokenProvider.buildUniqueToken();
        Optional<UserToken> optional = userTokenDao.findByEmailAndType(email, tokenType);
        if (optional.isPresent()) {
            userToken = optional.get();
            userToken.setToken(token);
        } else {
            userToken = new UserToken(email, token, "", "", tokenType, null);
        }
        return userToken;
    }

    public UserToken updateOAuth2Token(
            String email,
            String accessToken,
            String refreshToken,
            Integer expirationMinutes,
            JWTTokenPayload payload) throws JsonProcessingException {

        UserToken userToken;
        Optional<UserToken> optional = userTokenDao.findByToken(accessToken);
        if (optional.isPresent()) {
            userToken = optional.get();
        } else {
            optional = userTokenDao.findByEmailAndType(email, UserTokenType.OAUTH2);
            if (optional.isPresent()) {
                userToken = optional.get();
            } else {
                userToken = userTokenDao.save(new UserToken(email, "", "", "", UserTokenType.OAUTH2, new Date()));
            }
        }
        return updateOAuth2Token(userToken, email, accessToken, refreshToken, expirationMinutes, payload);
    }

    @Transactional
    public UserToken updateOAuth2Token(
            UserToken userToken,
            String email,
            String accessToken,
            String refreshToken,
            Integer expirationMinutes,
            JWTTokenPayload payload) throws JsonProcessingException {

        payload.setUserTokenId(userToken.getUuid());
        payload.setRecipientEmail(email);

        ObjectMapper mapper = new ObjectMapper();
        String subject = mapper.writeValueAsString(payload);

        String jwtToken = JWT.create()
                .withSubject(subject)
                .withExpiresAt(new Date(System.currentTimeMillis() + (expirationMinutes * 60000l)))
                .sign(HMAC512(secret.getBytes()));

//        expirationMinutes = 1;
        userToken.resetVerificationExpiryDate(expirationMinutes);
        userToken.setToken(accessToken);
        userToken.setRefreshToken(refreshToken);
        userToken.setPayload(jwtToken);

        return userTokenDao.save(userToken);
    }

    @Transactional
    public UserToken createAuthorizationToken(String recipientEmail, JWTTokenPayload payload, Integer expirationMinutes) throws JsonProcessingException {

        UserToken userToken;
        Optional<UserToken> optional = userTokenDao.findByEmailAndType(recipientEmail, UserTokenType.AUTHORIZATION);
        if (optional.isPresent()) {
            userToken = optional.get();
        } else {
            userToken = userTokenDao.save(new UserToken(recipientEmail, "", "", "", UserTokenType.AUTHORIZATION, new Date()));
        }

        payload.setUserTokenId(userToken.getUuid());
        payload.setRecipientEmail(recipientEmail);

        ObjectMapper mapper = new ObjectMapper();
        String subject = mapper.writeValueAsString(payload);

        String token = JWT.create()
                .withSubject(subject)
                .withExpiresAt(new Date(System.currentTimeMillis() + (expirationMinutes * 60000l)))
                .sign(HMAC512(secret.getBytes()));

        userToken.resetVerificationExpiryDate(expirationMinutes);
        userToken.setToken(new StringBuilder(authorizationPrefix).append(token).toString());

        return userTokenDao.save(userToken);
    }

    public Boolean isTokenValid(String token) {
        if (token == null) {
            return false;
        }
        try {
            JWT.require(HMAC512(secret.getBytes()))
                    .build()
                    .verify(token);
            return true;
        } catch (JWTVerificationException e) {
        }
        return false;
    }

    public <T extends JWTTokenPayload> T decodeAuthorizationToken(String token, ClassLoader classLoader, Boolean remove) {
        if (token == null) {
            throw new ErrorCodedHttpException(HttpStatus.BAD_REQUEST, AuthErrorCodes.NO_TOKEN);
        }
        if (token.startsWith(bearerPrefix)) {
            token = token.replace(bearerPrefix, "");
        }
        if (token.startsWith(authorizationPrefix)) {
            token = token.replace(authorizationPrefix, "");
        }

        try {
            String subject = JWT.require(HMAC512(secret.getBytes()))
                    .build()
                    .verify(token)
                    .getSubject();

            ObjectMapper mapper = new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JWTTokenPayload payload = mapper.readValue(subject, JWTTokenPayload.class);

            Optional<UserToken> optional = userTokenDao.findById(payload.getUserTokenId());
            if (!optional.isPresent()) {
                throw new ErrorCodedHttpException(HttpStatus.UNAUTHORIZED, AuthErrorCodes.TOKEN_EXPIRED, "No token found");
            }

            UserToken userToken = optional.get();
            if (userToken.isExpired()) {
                throw new ErrorCodedHttpException(HttpStatus.UNAUTHORIZED, AuthErrorCodes.TOKEN_EXPIRED, "Token expired");
            }

            Class clazz = classLoader != null ?
                    classLoader.loadClass(payload.getTokenType()) :
                    Class.forName(payload.getTokenType());

            T result = (T) mapper.readValue(subject, clazz);

            if (remove) {
                userTokenDao.delete(userToken);
            }
            return result;
        } catch (JWTVerificationException e) {
            throw new ErrorCodedHttpException(HttpStatus.UNAUTHORIZED, AuthErrorCodes.TOKEN_EXPIRED);
        } catch (IOException | ClassNotFoundException e) {
            throw new ErrorCodedHttpException(HttpStatus.INTERNAL_SERVER_ERROR, AuthErrorCodes.BAD_TOKEN, e);
        }
    }
}
