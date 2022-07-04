package com.github.archongum.hiveserver.custom.auth.ldap;

import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import com.github.archongum.hiveserver.custom.auth.common.LdapClient;
import com.github.archongum.hiveserver.custom.auth.common.LdapQuery;
import com.google.common.collect.ImmutableSet;
import static java.util.Objects.requireNonNull;

public class LdapAuthenticatorClient
{
    private final LdapClient ldapClient;

    public LdapAuthenticatorClient(LdapClient ldapClient)
    {
        this.ldapClient = requireNonNull(ldapClient, "ldapClient is null");
    }

    public void validatePassword(String userDistinguishedName, String password)
            throws NamingException
    {
        ldapClient.processLdapContext(userDistinguishedName, password, context -> null);
    }

    public boolean isGroupMember(String searchBase, String groupSearch, String contextUserDistinguishedName, String contextPassword)
            throws NamingException
    {
        return ldapClient.executeLdapQuery(
                contextUserDistinguishedName,
                contextPassword,
                new LdapQuery.LdapQueryBuilder()
                        .withSearchBase(searchBase)
                        .withSearchFilter(groupSearch).build(),
                NamingEnumeration::hasMore);
    }

    public Set<String> lookupUserDistinguishedNames(String searchBase, String searchFilter, String contextUserDistinguishedName, String contextPassword)
            throws NamingException
    {
        return ldapClient.executeLdapQuery(
                contextUserDistinguishedName,
                contextPassword,
                new LdapQuery.LdapQueryBuilder()
                        .withSearchBase(searchBase)
                        .withSearchFilter(searchFilter)
                        .build(),
                searchResults -> {
                    ImmutableSet.Builder<String> distinguishedNames = ImmutableSet.builder();
                    while (searchResults.hasMore()) {
                        distinguishedNames.add(searchResults.next().getNameInNamespace());
                    }
                    return distinguishedNames.build();
                });
    }
}
