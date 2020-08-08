package com.tubebreakup.authorization.model.userToken;

import com.tubebreakup.model.BaseEntityDao;
import com.tubebreakup.model.config.AppConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;

@Component
@Slf4j
public class UserTokenDao extends BaseEntityDao<UserToken> {
    @Autowired
    private UserTokenRepository repository;

    private AppConfig appConfig;

    @Override
    @CachePut(cacheNames="UserTokenCache", key="#entity.uuid", unless="#entity == null")
    public UserToken save(UserToken entity) {
        if (entity == null) {
            return null;
        }
        evict(entity);
        return repository.save(entity);
    }

    @Override
    @Cacheable(cacheNames="UserTokenCache", key="ALL", unless="#result == null")
    public List<UserToken> _findAll() {
        return repository.findAll();
    }

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

    @Override
    @Cacheable(cacheNames="UserTokenCache", key="#id", unless="#result == null")
    public Optional<UserToken> _findById(String id) {
        return null;
    }

    @Override
    @CachePut(cacheNames="UserTokenCache", key="#id", unless="#result == null")
    public Optional<UserToken> _fetchById(String id) {
        return repository.findById(id);
    }

    public Optional<UserToken> findByEmailAndType(String email, UserTokenType type) {
        if (!StringUtils.hasLength(email) || type == null) {
            return Optional.empty();
        }
        if (!getAppConfig().getEntityCacheEnabled()) {
            log.debug("CACHE DISABLED {} {}", email, type);
            return _fetchByEmailAndType(email, type);
        }

        Optional<UserToken> entity = _findByEmailAndType(email, type);
        if (entity != null) {
            log.debug("CACHE HIT {} {}", email, type);
            return entity;
        }

        log.debug("CACHE MISS {} {}", email, type);
        return _fetchByEmailAndType(email, type);
    }

    @Cacheable(cacheNames="UserTokenCache", key="#email.concat('.').concat(#type.value)", unless="#result == null")
    public Optional<UserToken> _findByEmailAndType(String email, UserTokenType type) {
        return null;
    }

    @CachePut(cacheNames="UserTokenCache", key="#email.concat('.').concat(#type.value)", unless="#result == null")
    public Optional<UserToken> _fetchByEmailAndType(String email, UserTokenType type) {
        return repository.findByEmailAndType(email, type);
    }

    public Optional<UserToken> findByToken(String token) {
        if (!StringUtils.hasLength(token)) {
            return Optional.empty();
        }
        if (!getAppConfig().getEntityCacheEnabled()) {
            log.debug("CACHE DISABLED {}", token);
            return _fetchByToken(token);
        }

        Optional<UserToken> entity = _findByToken(token);
        if (entity != null) {
            log.debug("CACHE HIT {}", token);
            return entity;
        }

        log.debug("CACHE MISS {}", token);
        return _fetchByToken(token);
    }

    @Cacheable(cacheNames="UserTokenCache", key="#token", unless="#result == null")
    public Optional<UserToken> _findByToken(String token) {
        return null;
    }

    @CachePut(cacheNames="UserTokenCache", key="#token", unless="#result == null")
    public Optional<UserToken> _fetchByToken(String token) {
        return repository.findByToken(token);
    }

    @Override
    @CacheEvict(cacheNames="UserTokenCache", key="#id")
    public void deleteById(String id) {
        Optional<UserToken> optional = findById(id);
        if (optional.isPresent()) {
            evict(optional.get());
        }
        repository.deleteById(id);
    }

    @Override
    @CacheEvict(cacheNames="UserTokenCache", key="#entity.uuid")
    public void delete(UserToken entity) {
        if (entity == null) {
            return;
        }
        evict(entity);
        repository.delete(entity);
    }

    @Override
    public void deleteAll() {
        repository.deleteAll();
        getCache().clear();
    }

    private String compositeKey(String email, UserTokenType type) {
        return new StringBuilder(email)
                .append('.')
                .append(type.value())
                .toString();
    }

    protected Cache getCache() {
        return cacheManager.getCache("UserTokenCache");
    }

    @Override
    protected void evict(UserToken entity) {
        if (entity == null) {
            return;
        }
        super.evict(entity);
        getCache().evict(entity.getToken());
        getCache().evict(compositeKey(entity.getEmail(), entity.getType()));
    }
}