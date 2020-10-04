package com.tubebreakup.authorization.model.user;

import java.util.Set;

public interface AuthUser {
    Set<AuthUserRole> getRoles();
}
