# hiveserver-custom-auth

# Compatibility

- Hadoop 2.7
- Hive 1.2

For other version, change the hadoop/hive dependencies version in `pom.xml` then compile.

# Compile or Download

Compile

```bash
mvn clean package
```

Download pre-compile in [Releases](https://github.com/archongum/hiveserver-custom-auth/releases)

# Installation

Copy `hiveserver-custom-auth-${version}-jar-with-dependencies.jar` to Hive `lib` directory.
For HDP, the path is `/usr/hdp/current/hive-client/lib/`

# Usage

There are two `authenticator` in ths project.

- HS2SimpleAuthenticator
- HS2LdapAuthenticator

## HS2SimpleAuthenticator

This authenticator requires no external username/password storage.
It's self-authenticated with a simple rule which can be improvised also.

### 1. Configuration

Add to `hive-site.xml` and Restart `HiveServer2`

```xml
<property>
  <name>hive.server2.authentication</name>
  <value>CUSTOM</value>
</property>
<property>
  <name>hive.server2.custom.authentication.class</name>
  <value>com.github.archongum.hiveserver.custom.auth.authenticator.HS2SimpleAuthenticator</value>
</property>
```

### 2. Authentication

`password` equals any 6-characters string concats baes64(`username`)

e.g. Username is `hive`, the base64 of `hive` is `aGl2ZQ==`, then password is `123456aGl2ZQ==` or `sixsixaGl2ZQ==` or `asdfghaGl2ZQ==` or etc.

For beeline:

```bash
beeline -u "jdbc:hive2://localhost:10000/default" -n hive -p asdfghaGl2ZQ==
```

FYI

```bash
$ echo -n "hive" | base64
aGl2ZQ==
```


## HS2LdapAuthenticator

This authenticator requires a `LDAP` server.

There are two use-cases:

- user-pattern:  No additional ldap user configuration
- group-pattern: Requires a privileged ldap user

### 1. Configuration

Add to `hive-site.xml` and Restart `HiveServer2`

#### user-pattern

```xml
<!-- hive conf -->
<property>
  <name>hive.server2.authentication</name>
  <value>CUSTOM</value>
</property>
<property>
  <name>hive.server2.custom.authentication.class</name>
  <value>com.github.archongum.hiveserver.custom.auth.authenticator.HS2LdapAuthenticator</value>
</property>

<!-- HS2LdapAuthenticator conf -->
<property>
  <name>hive.server2.custom.authentication.ldap.url</name>
  <value>ldap://ldap_host:389</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.user-bind-pattern</name>
  <value>uid=${USER},ou=employee,o=company_name</value>
</property>
```

#### group-pattern

```xml
<!-- hive conf -->
<property>
  <name>hive.server2.authentication</name>
  <value>CUSTOM</value>
</property>
<property>
  <name>hive.server2.custom.authentication.class</name>
  <value>com.github.archongum.hiveserver.custom.auth.authenticator.HS2LdapAuthenticator</value>
</property>

<!-- HS2LdapAuthenticator conf -->
<property>
  <name>hive.server2.custom.authentication.ldap.url</name>
  <value>ldap://ldap_host:389</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.user-bind-pattern</name>
  <value>uid=${USER},ou=employee,o=company_name</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.user-base-dn</name>
  <value>ou=employee,o=company_name</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.group-auth-pattern</name>
  <value>(&amp;(uid=${USER})(!(gidNumber=10007))(memberOf=cn=grafana,ou=groups,ou=apps,o=company_name))</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.bind-dn</name>
  <value>cn=ldap_auth_user01,ou=users,ou=apps,o=company_name</value>
</property>
<property>
  <name>hive.server2.custom.authentication.ldap.bind-password</name>
  <value>ldap_auth_user01_password</value>
</property>
```

#### 2. Authentication

For beeline:

```bash
beeline -u "jdbc:hive2://localhost:10000/default" -n my_ldap_username -p my_ldap_password
```
