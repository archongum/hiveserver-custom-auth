package com.github.archongum.hiveserver.custom.auth.authenticator;

import java.io.File;
import javax.security.sasl.AuthenticationException;
import com.github.archongum.hiveserver.custom.auth.common.JdkLdapClient;
import com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig;
import com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticator;
import com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorClient;
import com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig;
import io.airlift.units.Duration;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hive.service.auth.PasswdAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.ALLOW_INSECURE;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.IGNORE_REFERRALS;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.KEYSTORE_PASSWORD;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.KEYSTORE_PATH;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.LDAP_CONNECTION_TIMEOUT;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.LDAP_READ_TIMEOUT;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.LDAP_URL;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.TRUSTSTORE_PASSWORD;
import static com.github.archongum.hiveserver.custom.auth.common.LdapClientConfig.TRUSTSTORE_PATH;
import static com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig.BIND_DN;
import static com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig.BIND_PASSWORD;
import static com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig.GROUP_AUTHORIZATION_SEARCH_PATTERN;
import static com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig.USER_BASE_DN;
import static com.github.archongum.hiveserver.custom.auth.ldap.LdapAuthenticatorConfig.USER_BIND_SEARCH_PATTERNS;


/**
 * LDAP Authenticator
 *
 * @author Archon  2022/7/1
 * @since
 */
public class HS2LdapAuthenticator implements PasswdAuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(HS2LdapAuthenticator.class);

    private final LdapAuthenticator authenticator;

    public HS2LdapAuthenticator() {
        this.authenticator = createLdapAuthenticator(new Configuration(new HiveConf()));
    }


    @Override
    public void Authenticate(String username, String  password) throws AuthenticationException {
        try {
            authenticator.authenticateWithUserBind(username, password);
        } catch (Exception e) {
            log.warn("User: [{}] login error: {}", username, e.getMessage());
            throw new AuthenticationException(String.format("User: [%s] login error: %s", username, e.getMessage()));
        }
        log.info("User: [{}] login success", username);
    }

    private LdapAuthenticator createLdapAuthenticator(Configuration configuration) {
        LdapClientConfig ldapClientConfig =
            new LdapClientConfig()
                .setLdapUrl(configuration.get(LDAP_URL))
                .setAllowInsecure(configuration.getBoolean(ALLOW_INSECURE, true))
                .setKeystorePassword(configuration.get(KEYSTORE_PASSWORD))
                .setTruststorePassword(configuration.get(TRUSTSTORE_PASSWORD))
                .setIgnoreReferrals(configuration.getBoolean(IGNORE_REFERRALS, true));
        if (configuration.get(KEYSTORE_PATH) != null) {
            ldapClientConfig.setKeystorePath(new File(configuration.get(KEYSTORE_PATH)));
        }
        if (configuration.get(TRUSTSTORE_PATH) != null) {
            ldapClientConfig.setTrustStorePath(new File(configuration.get(TRUSTSTORE_PATH)));
        }
        if (configuration.get(LDAP_CONNECTION_TIMEOUT) != null) {
            ldapClientConfig.setLdapConnectionTimeout(Duration.valueOf(configuration.get(LDAP_CONNECTION_TIMEOUT)));
        }
        if (configuration.get(LDAP_READ_TIMEOUT) != null) {
            ldapClientConfig.setLdapReadTimeout(Duration.valueOf(configuration.get(LDAP_READ_TIMEOUT)));
        }
        JdkLdapClient jdkLdapClient = new JdkLdapClient(ldapClientConfig);
        LdapAuthenticatorClient client = new LdapAuthenticatorClient(jdkLdapClient);
        LdapAuthenticatorConfig config =
            new LdapAuthenticatorConfig()
                .setUserBindSearchPatterns(configuration.get(USER_BIND_SEARCH_PATTERNS))
                .setGroupAuthorizationSearchPattern(configuration.get(GROUP_AUTHORIZATION_SEARCH_PATTERN))
                .setUserBaseDistinguishedName(configuration.get(USER_BASE_DN))
                .setBindDistingushedName(configuration.get(BIND_DN))
                .setBindPassword(configuration.get(BIND_PASSWORD));
        return new LdapAuthenticator(client, config);
    }

    /**
     * Getter
     *
     * @return
     */
    public LdapAuthenticator getAuthenticator() {
        return this.authenticator;
    }
}
