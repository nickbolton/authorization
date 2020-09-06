package com.tubebreakup.authorization.model.userToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface UserTokenRepository extends JpaRepository<UserToken, String> {
  Optional<UserToken> findByEmailAndType(String email, UserTokenType type);
  Optional<UserToken> findByToken(String token);
  Optional<UserToken> findByRefreshToken(String refreshToken);

  @Modifying
  @Query("delete from UserToken t where t.type != 'OAUTH2' AND t.expirationDate <= :now")
  void deleteAllExpiredSince(Date now);
}
