package com.tubebreakup.authorization.model.user;

public interface AuthUserDao {
    <T> T findById(String id);
}
