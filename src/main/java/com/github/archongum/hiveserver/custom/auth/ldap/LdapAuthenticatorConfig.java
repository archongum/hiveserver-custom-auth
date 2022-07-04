package com.github.archongum.hiveserver.custom.auth.ldap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.validation.constraints.NotNull;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import static java.util.Objects.requireNonNull;

public class LdapAuthenticatorConfig
{
    public static final String USER_BIND_SEARCH_PATTERNS          = "hive.server2.custom.authentication.ldap.user-bind-pattern";
    public static final String GROUP_AUTHORIZATION_SEARCH_PATTERN = "hive.server2.custom.authentication.ldap.group-auth-pattern";
    public static final String USER_BASE_DN                       = "hive.server2.custom.authentication.ldap.user-base-dn";
    public static final String BIND_DN                            = "hive.server2.custom.authentication.ldap.bind-dn";
    public static final String BIND_PASSWORD                      = "hive.server2.custom.authentication.ldap.bind-password";

    private List<String> userBindSearchPatterns = ImmutableList.of();
    private String groupAuthorizationSearchPattern;
    private String userBaseDistinguishedName;
    private String bindDistinguishedName;
    private String bindPassword;

    @NotNull
    public List<String> getUserBindSearchPatterns()
    {
        return userBindSearchPatterns;
    }

    public LdapAuthenticatorConfig setUserBindSearchPatterns(List<String> userBindSearchPatterns)
    {
        this.userBindSearchPatterns = requireNonNull(userBindSearchPatterns, "userBindSearchPatterns is null");
        return this;
    }

//    @Config("ldap.user-bind-pattern")
//    @ConfigDescription("Custom user bind pattern. Example: ${USER}@example.com")
    public LdapAuthenticatorConfig setUserBindSearchPatterns(String userBindSearchPatterns)
    {
        List<String> result = new ArrayList<>();
        for (String s : Splitter.on(":").trimResults().omitEmptyStrings().split(userBindSearchPatterns)) {
            result.add(s);
        }
        this.userBindSearchPatterns = Collections.unmodifiableList(result);
        return this;
    }

    public String getGroupAuthorizationSearchPattern()
    {
        return groupAuthorizationSearchPattern;
    }

//    @Config("ldap.group-auth-pattern")
//    @ConfigDescription("Custom group authorization check query. Example: &(objectClass=user)(memberOf=cn=group)(user=username)")
    public LdapAuthenticatorConfig setGroupAuthorizationSearchPattern(String groupAuthorizationSearchPattern)
    {
        this.groupAuthorizationSearchPattern = groupAuthorizationSearchPattern;
        return this;
    }

    public String getUserBaseDistinguishedName()
    {
        return userBaseDistinguishedName;
    }

//    @Config("ldap.user-base-dn")
//    @ConfigDescription("Base distinguished name of the user. Example: dc=example,dc=com")
    public LdapAuthenticatorConfig setUserBaseDistinguishedName(String userBaseDistinguishedName)
    {
        this.userBaseDistinguishedName = userBaseDistinguishedName;
        return this;
    }

    public String getBindDistingushedName()
    {
        return bindDistinguishedName;
    }

//    @Config("ldap.bind-dn")
//    @ConfigDescription("Bind distinguished name. Example: CN=User Name,OU=CITY_OU,OU=STATE_OU,DC=domain,DC=domain_root")
    public LdapAuthenticatorConfig setBindDistingushedName(String bindDistingushedName)
    {
        this.bindDistinguishedName = bindDistingushedName;
        return this;
    }

    public String getBindPassword()
    {
        return bindPassword;
    }

//    @Config("ldap.bind-password")
//    @ConfigDescription("Bind password used. Example: password1234")
    public LdapAuthenticatorConfig setBindPassword(String bindPassword)
    {
        this.bindPassword = bindPassword;
        return this;
    }
}
