package com.github.archongum.hiveserver.custom.auth.common;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Optional;
import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.net.ssl.SSLContext;
import com.google.common.collect.ImmutableMap;
import io.airlift.units.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static java.util.Objects.requireNonNull;
import static javax.naming.Context.INITIAL_CONTEXT_FACTORY;
import static javax.naming.Context.PROVIDER_URL;
import static javax.naming.Context.REFERRAL;
import static javax.naming.Context.SECURITY_AUTHENTICATION;
import static javax.naming.Context.SECURITY_CREDENTIALS;
import static javax.naming.Context.SECURITY_PRINCIPAL;

public class JdkLdapClient
        implements LdapClient
{
    private static final Logger log = LoggerFactory.getLogger(JdkLdapClient.class);
    private final Map<String, String> basicEnvironment;
    private final Optional<SSLContext> sslContext;

    public JdkLdapClient(LdapClientConfig ldapConfig)
    {
        String ldapUrl = requireNonNull(ldapConfig.getLdapUrl(), "ldapUrl is null");
        if (ldapUrl.startsWith("ldap://")) {
            log.warn("Passwords will be sent in the clear to the LDAP server. Please consider using SSL to connect.");
        }

        ImmutableMap.Builder<String, String> builder = ImmutableMap.builder();

        builder.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
                .put(PROVIDER_URL, ldapUrl)
                .put(REFERRAL, ldapConfig.isIgnoreReferrals() ? "ignore" : "follow");

        ldapConfig.getLdapConnectionTimeout()
                .map(Duration::toMillis)
                .map(String::valueOf)
                .ifPresent(timeout -> builder.put("com.sun.jndi.ldap.connect.timeout", timeout));

        ldapConfig.getLdapReadTimeout()
                .map(Duration::toMillis)
                .map(String::valueOf)
                .ifPresent(timeout -> builder.put("com.sun.jndi.ldap.read.timeout", timeout));

        this.basicEnvironment = builder.build();

        this.sslContext = createSslContext(
                ldapConfig.getKeystorePath(),
                ldapConfig.getKeystorePassword(),
                ldapConfig.getTrustStorePath(),
                ldapConfig.getTruststorePassword());
    }

    @Override
    public <T> T processLdapContext(String userName, String password, LdapContextProcessor<T> contextProcessor)
            throws NamingException
    {
        try (CloseableContext context = createUserDirContext(userName, password)) {
            return contextProcessor.process(context.context);
        }
    }

    @Override
    public <T> T executeLdapQuery(String userName, String password, LdapQuery ldapQuery, LdapSearchResultProcessor<T> resultProcessor)
            throws NamingException
    {
        try (CloseableContext context = createUserDirContext(userName, password);
                CloseableSearchResults search = searchContext(ldapQuery, context)) {
            return resultProcessor.process(search.searchResults);
        }
    }

    private static CloseableSearchResults searchContext(LdapQuery ldapQuery, CloseableContext context)
            throws NamingException
    {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(ldapQuery.getAttributes());
        return new CloseableSearchResults(context.search(ldapQuery.getSearchBase(), ldapQuery.getSearchFilter(), searchControls));
    }

    private CloseableContext createUserDirContext(String userDistinguishedName, String password)
            throws NamingException
    {
        Map<String, String> environment = createEnvironment(userDistinguishedName, password);
        try {
            // This is the actual Authentication piece. Will throw javax.naming.AuthenticationException
            // if the users password is not correct. Other exceptions may include IO (server not found) etc.
            DirContext context = createDirContext(environment);
            log.debug("Password validation successful for user DN [%s]", userDistinguishedName);
            return new CloseableContext(context);
        }
        catch (AuthenticationException e) {
            log.debug("Password validation failed for user DN [%s]: %s", userDistinguishedName, e.getMessage());
            throw new AuthenticationException("Invalid credentials");
        }
    }

    private Map<String, String> createEnvironment(String userDistinguishedName, String password)
    {
        ImmutableMap.Builder<String, String> environment = ImmutableMap.<String, String>builder()
                .putAll(basicEnvironment)
                .put(SECURITY_AUTHENTICATION, "simple")
                .put(SECURITY_PRINCIPAL, userDistinguishedName)
                .put(SECURITY_CREDENTIALS, password);

        sslContext.ifPresent(context -> {
            LdapSslSocketFactory.setSslContextForCurrentThread(context);

            // see https://docs.oracle.com/javase/jndi/tutorial/ldap/security/ssl.html
            environment.put("java.naming.ldap.factory.socket", LdapSslSocketFactory.class.getName());
        });

        return environment.build();
    }

    private static Optional<SSLContext> createSslContext(
            Optional<File> keyStorePath,
            Optional<String> keyStorePassword,
            Optional<File> trustStorePath,
            Optional<String> trustStorePassword)
    {
        if (!keyStorePath.isPresent() && !trustStorePath.isPresent()) {
            return Optional.empty();
        }
        try {
            return Optional.of(SslUtils.createSSLContext(keyStorePath, keyStorePassword, trustStorePath, trustStorePassword));
        }
        catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static class CloseableContext
            implements AutoCloseable
    {
        private final DirContext context;

        public CloseableContext(DirContext context)
        {
            this.context = requireNonNull(context, "context is null");
        }

        public NamingEnumeration<SearchResult> search(String name, String filter, SearchControls searchControls)
                throws NamingException
        {
            return context.search(name, filter, searchControls);
        }

        @Override
        public void close()
                throws NamingException
        {
            context.close();
        }
    }

    public static DirContext createDirContext(Map<String, String> environment)
        throws NamingException
    {
        return new InitialDirContext(new Hashtable<>(environment));
    }

    private static class CloseableSearchResults
            implements AutoCloseable
    {
        private final NamingEnumeration<SearchResult> searchResults;

        public CloseableSearchResults(NamingEnumeration<SearchResult> searchResults)
        {
            this.searchResults = requireNonNull(searchResults, "searchResults is null");
        }

        public NamingEnumeration<SearchResult> getSearchResult()
                throws NamingException
        {
            return searchResults;
        }

        @Override
        public void close()
                throws NamingException
        {
            searchResults.close();
        }
    }
}
