package com.github.archongum.hiveserver.custom.auth.authenticator;

import javax.security.sasl.AuthenticationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled
class HS2SimpleAuthenticatorTest {
    static HS2SimpleAuthenticator authenticator;

    @BeforeAll
    static void before() {
        authenticator = new HS2SimpleAuthenticator();
    }

    @Test
    void authOk() throws AuthenticationException {
        String user = "hive";
        String password = "asdfghaGl2ZQ==";
        authenticator.Authenticate(user, password);
    }

    @Test
    void authFailed() {
        String user = "hive";
        String password = "asdfghaGl2ZQ=";
        Assertions.assertThrows(AuthenticationException.class, () -> authenticator.Authenticate(user, password));
    }
}
