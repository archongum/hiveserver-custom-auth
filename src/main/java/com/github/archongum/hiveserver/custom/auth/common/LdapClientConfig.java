package com.github.archongum.hiveserver.custom.auth.common;

import java.io.File;
import java.util.Optional;
import javax.validation.constraints.AssertTrue;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import io.airlift.units.Duration;
import static com.google.common.base.Strings.nullToEmpty;


public class LdapClientConfig {

    public static final String LDAP_URL                = "hive.server2.custom.authentication.ldap.url";
    public static final String ALLOW_INSECURE          = "hive.server2.custom.authentication.ldap.allow-insecure";
    public static final String KEYSTORE_PATH           = "hive.server2.custom.authentication.ldap.ssl.keystore.path";
    public static final String KEYSTORE_PASSWORD       = "hive.server2.custom.authentication.ldap.ssl.keystore.password";
    public static final String TRUSTSTORE_PATH         = "hive.server2.custom.authentication.ldap.ssl.truststore.path";
    public static final String TRUSTSTORE_PASSWORD     = "hive.server2.custom.authentication.ldap.ssl.truststore.password";
    public static final String IGNORE_REFERRALS        = "hive.server2.custom.authentication.ldap.ignore-referrals";
    public static final String LDAP_CONNECTION_TIMEOUT = "hive.server2.custom.authentication.ldap.timeout.connect";
    public static final String LDAP_READ_TIMEOUT       = "hive.server2.custom.authentication.ldap.timeout.read";

    private String ldapUrl;

    private boolean allowInsecure;

    private File keystorePath;

    private String keystorePassword;

    private File trustStorePath;

    private String truststorePassword;

    private boolean ignoreReferrals;

    private Optional<Duration> ldapConnectionTimeout = Optional.empty();

    private Optional<Duration> ldapReadTimeout = Optional.empty();

    @NotNull
    @Pattern(regexp = "^ldaps?://.*", message = "Invalid LDAP server URL. Expected ldap:// or ldaps://")
    public String getLdapUrl() {
        return ldapUrl;
    }

    //    @Config("ldap.url")
//    @ConfigDescription("URL of the LDAP server")
    public LdapClientConfig setLdapUrl(String url) {
        this.ldapUrl = url;
        return this;
    }

    public boolean isAllowInsecure() {
        return allowInsecure;
    }

    //    @Config("ldap.allow-insecure")
//    @ConfigDescription("Allow insecure connection to the LDAP server")
    public LdapClientConfig setAllowInsecure(boolean allowInsecure) {
        this.allowInsecure = allowInsecure;
        return this;
    }

    @AssertTrue(message = "Connecting to the LDAP server without SSL enabled requires `ldap.allow-insecure=true`")
    public boolean isUrlConfigurationValid() {
        return nullToEmpty(ldapUrl).startsWith("ldaps://") || allowInsecure;
    }

    public Optional<File> getKeystorePath() {
        return Optional.ofNullable(keystorePath);
    }

    //    @Config("ldap.ssl.keystore.path")
//    @ConfigDescription("Path to the PEM or JKS key store")
    public LdapClientConfig setKeystorePath(File path) {
        this.keystorePath = path;
        return this;
    }

    public Optional<String> getKeystorePassword() {
        return Optional.ofNullable(keystorePassword);
    }

    //    @Config("ldap.ssl.keystore.password")
//    @ConfigDescription("Password for the key store")
    public LdapClientConfig setKeystorePassword(String password) {
        this.keystorePassword = password;
        return this;
    }

    public Optional<File> getTrustStorePath() {
        return Optional.ofNullable(trustStorePath);
    }

    //    @Config("ldap.ssl.truststore.path")
//    @ConfigDescription("Path to the PEM or JKS trust store")
    public LdapClientConfig setTrustStorePath(File path) {
        this.trustStorePath = path;
        return this;
    }

    public Optional<String> getTruststorePassword() {
        return Optional.ofNullable(truststorePassword);
    }

    //    @Config("ldap.ssl.truststore.password")
//    @ConfigDescription("Password for the trust store")
    public LdapClientConfig setTruststorePassword(String password) {
        this.truststorePassword = password;
        return this;
    }

    public boolean isIgnoreReferrals() {
        return ignoreReferrals;
    }

    //    @Config("ldap.ignore-referrals")
//    @ConfigDescription("Referrals allow finding entries across multiple LDAP servers. Ignore them to only search within 1 LDAP server")
    public LdapClientConfig setIgnoreReferrals(boolean ignoreReferrals) {
        this.ignoreReferrals = ignoreReferrals;
        return this;
    }

    public Optional<Duration> getLdapConnectionTimeout() {
        return ldapConnectionTimeout;
    }

    //    @Config("ldap.timeout.connect")
//    @ConfigDescription("Timeout for establishing a connection")
    public LdapClientConfig setLdapConnectionTimeout(Duration ldapConnectionTimeout) {
        this.ldapConnectionTimeout = Optional.ofNullable(ldapConnectionTimeout);
        return this;
    }

    public Optional<Duration> getLdapReadTimeout() {
        return ldapReadTimeout;
    }

    //    @Config("ldap.timeout.read")
//    @ConfigDescription("Timeout for reading data from LDAP")
    public LdapClientConfig setLdapReadTimeout(Duration ldapReadTimeout) {
        this.ldapReadTimeout = Optional.ofNullable(ldapReadTimeout);
        return this;
    }
}
