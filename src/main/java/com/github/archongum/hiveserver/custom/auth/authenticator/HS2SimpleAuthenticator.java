package com.github.archongum.hiveserver.custom.auth.authenticator;

import java.util.Base64;
import javax.security.sasl.AuthenticationException;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *  Simpler way:
 *
 *  ```bash
 *  javac -cp /usr/hdp/current/hive-client/lib/hive-service.jar hiveserver/custom/auth/HS2CustomAuthenticator.java
 *  jar cf hiveserver-custom-auth-1.0.jar hiveserver/
 *  mv hiveserver-custom-auth-1.0.jar /usr/hdp/current/hive-client/lib/
 *  ```
 * @author Archon  2022/7/1
 * @since
 */
public class HS2SimpleAuthenticator implements PasswdAuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(HS2SimpleAuthenticator.class);

    @Override
    public void Authenticate(String username, String  password) throws AuthenticationException {
        try {
            if (!username.equals(new String(Base64.getDecoder().decode(password.substring(6))))) {
                log.warn("User: [{}] password incorrect", username);
                throw new AuthenticationException(String.format("User: [%s] password incorrect", username));
            }
        } catch (RuntimeException e) {
            log.warn("User: [{}] login error: {}", username, e.getMessage());
            throw new AuthenticationException(String.format("User: [%s] login error: %s", username, e.getMessage()));
        }
        log.info("User: [{}] login success", username);
    }
}
