package com.tubebreakup.authorization.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public class RefreshTokenProviderWrapper {
    @Getter
    RefreshTokenProvider provider;
    @Getter String refreshToken;
}
