package com.github.archongum.hiveserver.custom.auth.ldap;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.naming.NamingException;
import javax.security.sasl.AuthenticationException;
import com.github.archongum.hiveserver.custom.auth.common.BasicPrincipal;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.CharMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.Iterables.getOnlyElement;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class LdapAuthenticator {
    private static final CharMatcher SPECIAL_CHARACTERS = CharMatcher.anyOf(",=+<>#;*()\"\\\u0000");
    private static final CharMatcher WHITESPACE = CharMatcher.anyOf(" \r");

    private static final Logger log = LoggerFactory.getLogger(LdapAuthenticator.class);

    private final LdapAuthenticatorClient client;

    private final List<String> userBindSearchPatterns;
    private final Optional<String> groupAuthorizationSearchPattern;
    private final Optional<String> userBaseDistinguishedName;
    private final Optional<String> bindDistinguishedName;
    private final Optional<String> bindPassword;

    public LdapAuthenticator(LdapAuthenticatorClient client, LdapAuthenticatorConfig ldapAuthenticatorConfig)
    {
        this.client = requireNonNull(client, "client is null");

        this.userBindSearchPatterns = ldapAuthenticatorConfig.getUserBindSearchPatterns();
        this.groupAuthorizationSearchPattern = Optional.ofNullable(ldapAuthenticatorConfig.getGroupAuthorizationSearchPattern());
        this.userBaseDistinguishedName = Optional.ofNullable(ldapAuthenticatorConfig.getUserBaseDistinguishedName());
        this.bindDistinguishedName = Optional.ofNullable(ldapAuthenticatorConfig.getBindDistingushedName());
        this.bindPassword = Optional.ofNullable(ldapAuthenticatorConfig.getBindPassword());

        checkArgument(
                !groupAuthorizationSearchPattern.isPresent() || userBaseDistinguishedName.isPresent(),
                "Base distinguished name (DN) for user must be provided");
        checkArgument(
                bindDistinguishedName.isPresent() == bindPassword.isPresent(),
                "Both bind distinguished name and bind password must be provided together");
        checkArgument(
                !bindDistinguishedName.isPresent() || groupAuthorizationSearchPattern.isPresent(),
                "Group authorization search pattern must be provided when bind distinguished name is used");
        checkArgument(
                bindDistinguishedName.isPresent() || !userBindSearchPatterns.isEmpty(),
                "Either user bind search pattern or bind distinguished name must be provided");
    }

    public Principal authenticateWithUserBind(String user, String password) throws AuthenticationException {
        if (containsSpecialCharacters(user)) {
            throw new AuthenticationException("Username contains a special LDAP character");
        }
        Exception lastException = new RuntimeException();
        for (String userBindSearchPattern : userBindSearchPatterns) {
            try {
                String userDistinguishedName = replaceUser(userBindSearchPattern, user);
                if (groupAuthorizationSearchPattern.isPresent()) {
                    // user password is also validated as user DN and password is used for querying LDAP
                    String searchBase = userBaseDistinguishedName.get();
                    String groupSearch = replaceUser(groupAuthorizationSearchPattern.get(), user);
                    System.out.println(String.format("searchBase: %s\ngroupSearch: %s", searchBase, groupSearch));
                    if (!client.isGroupMember(searchBase, groupSearch, userDistinguishedName, password)) {
                        String message = format("User [%s] not a member of an authorized group", user);
                        log.info("{}", message);
                        throw new AuthenticationException(message);
                    }
                }
                else {
                    client.validatePassword(userDistinguishedName, password);
                }
                log.info("Authentication successful for user [{}]", user);
                return new BasicPrincipal(user);
            }
            catch (NamingException | AuthenticationException e) {
                lastException = e;
            }
        }
        log.warn("Authentication failed for user [{}], {}", user, lastException.getMessage());
        if (lastException instanceof AuthenticationException) {
            throw (AuthenticationException) lastException;
        }
        throw new RuntimeException("Authentication error");
    }

    public Principal authenticateWithBindDistinguishedName(String user, String password) throws AuthenticationException {
        if (containsSpecialCharacters(user)) {
            throw new AuthenticationException("Username contains a special LDAP character");
        }
        try {
            String userDistinguishedName = lookupUserDistinguishedName(user);
            client.validatePassword(userDistinguishedName, password);
            log.info("Authentication successful for user [{}]", user);
        }
        catch (NamingException e) {
            log.warn("Authentication failed for user [{}], {}", user, e.getMessage());
            throw new RuntimeException("Authentication error");
        }
        return new BasicPrincipal(user);
    }

    public Principal authenticateWithBindDistinguishedNameWithoutMemberOf(String user, String password) throws AuthenticationException {
        if (containsSpecialCharacters(user)) {
            throw new AuthenticationException("Username contains a special LDAP character");
        }
        try {
            if(isMemberInGroups(user)) {
                return authenticateWithUserBind(user, password);
            }
        }
        catch (NamingException e) {
            log.warn("Authentication failed for user [{}], {}", user, e.getMessage());
            throw new RuntimeException("Authentication error");
        }
        return new BasicPrincipal(user);
    }

    /**
     * Returns {@code true} when parameter contains a character that has a special meaning in
     * LDAP search or bind name (DN).
     * <p>
     * Based on <a href="https://www.owasp.org/index.php/Preventing_LDAP_Injection_in_Java">Preventing_LDAP_Injection_in_Java</a> and
     * {@link javax.naming.ldap.Rdn#escapeValue(Object) escapeValue} method.
     */
    @VisibleForTesting
    static boolean containsSpecialCharacters(String user)
    {
        if (WHITESPACE.indexIn(user) == 0 || WHITESPACE.lastIndexIn(user) == user.length() - 1) {
            return true;
        }
        return SPECIAL_CHARACTERS.matchesAnyOf(user);
    }

    private String lookupUserDistinguishedName(String user) throws NamingException, AuthenticationException {
        String searchBase = userBaseDistinguishedName.get();
        String searchFilter = replaceUser(groupAuthorizationSearchPattern.get(), user);
        System.out.println("searchBase: " + searchBase);
        System.out.println("searchFilter: " + searchFilter);
        Set<String> userDistinguishedNames = client.lookupUserDistinguishedNames(searchBase, searchFilter, bindDistinguishedName.get(), bindPassword.get());
        System.out.println(userDistinguishedNames.size());
        userDistinguishedNames.forEach(s -> {
            System.out.println(s);
        });

        if (userDistinguishedNames.isEmpty()) {
            String message = format("User [%s] not a member of an authorized group", user);
            log.info("{}", message);
            throw new AuthenticationException(message);
        }
        if (userDistinguishedNames.size() > 1) {
            String message = format("Multiple group membership results for user [%s]: %s", user, userDistinguishedNames);
            log.info("{}", message);
            throw new AuthenticationException(message);
        }
        return getOnlyElement(userDistinguishedNames);
    }

    private boolean isMemberInGroups(String user) throws NamingException, AuthenticationException {
        String searchBase = userBaseDistinguishedName.get();
        String searchFilter = replaceUser(groupAuthorizationSearchPattern.get(), user);
        Set<String> userDistinguishedNames = client.lookupUserDistinguishedNames(searchBase, searchFilter, bindDistinguishedName.get(), bindPassword.get());

        if (userDistinguishedNames.isEmpty()) {
            String message = format("User [%s] not a member of an authorized group", user);
            log.info("{}", message);
            throw new AuthenticationException(message);
        }
        return true;
    }

    private static String replaceUser(String pattern, String user)
    {
        return pattern.replace("${USER}", user);
    }
}
