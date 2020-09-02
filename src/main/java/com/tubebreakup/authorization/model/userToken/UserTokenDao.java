package com.tubebreakup.authorization.model.userToken;

import com.tubebreakup.model.BaseEntityDao;
import com.tubebreakup.model.cache.DefaultResourceCache;
import com.tubebreakup.model.config.AppConfig;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Component
@Slf4j
public class UserTokenDao extends BaseEntityDao<UserToken> {

    private final String NAMESPACE = "TubeBreakup";

    @Autowired
    @Getter
    private UserTokenRepository repository;

    private AppConfig appConfig;

    @Override
    protected AppConfig getAppConfig() {
        if (appConfig == null) {
            appConfig = new AppConfig() {
                @Override
                public Boolean getEntityCacheEnabled() {
                    return true;
                }
            };
        }
        return appConfig;
    }

    public Optional<UserToken> findByEmailAndType(String email, UserTokenType type) {
        if (!StringUtils.hasLength(email) || type == null) {
            return Optional.empty();
        }
        String key = compositeKey(email, type);
        return getOptionalFromCacheWithFallback(key, () -> _findByEmailAndType(email, type) );
    }

    public Optional<UserToken> _findByEmailAndType(String email, UserTokenType type) {
        return repository.findByEmailAndType(email, type);
    }

    public Optional<UserToken> findByToken(String token) {
        if (!StringUtils.hasLength(token)) {
            return Optional.empty();
        }
        return getOptionalFromCacheWithFallback(token, () -> repository.findByToken(token) );
    }

    private String compositeKey(String email, UserTokenType type) {
        if (email == null || type == null) {
            return null;
        }
        return new StringBuilder(email)
                .append('.')
                .append(type.value())
                .toString();
    }

    @Override
    protected void evictKeysForEntity(UserToken entity) {
        if (entity == null) {
            return;
        }
        evict(entity.getToken());
        evict(compositeKey(entity.getEmail(), entity.getType()));
    }

    @Override
    protected String getCacheNamespace() {
        return NAMESPACE;
    }

    @Override
    protected String getEntityName() {
        return UserToken.class.getSimpleName();
    }
}