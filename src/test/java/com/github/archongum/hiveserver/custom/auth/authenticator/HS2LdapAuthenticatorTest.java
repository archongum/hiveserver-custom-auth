package com.github.archongum.hiveserver.custom.auth.authenticator;

import javax.security.sasl.AuthenticationException;
import com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;


@Disabled
class HS2LdapAuthenticatorTest {
    static HS2LdapAuthenticator authenticator;

    @BeforeAll
    static void before() {
        authenticator = new HS2LdapAuthenticator();
    }

    @Test
    void authOk() throws AuthenticationException {
        String user = "test";
        String password = "test123";
        authenticator.Authenticate(user, password);
    }

    @Test
    void authFailed() {
        String user = "test";
        String password = "test";
        Assertions.assertThrows(AuthenticationException.class, () -> authenticator.Authenticate(user, password));
    }

    @Test
    void authGroup() throws AuthenticationException {
        String user = "test";
        String password = "test123";
        LdapAuthenticator inner = authenticator.getAuthenticator();
        inner.authenticateWithBindDistinguishedName(user, password);
    }
}
