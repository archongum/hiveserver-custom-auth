package com.github.archongum.hiveserver.custom.auth.common;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;


public interface LdapClient {

    <T> T processLdapContext(String userName, String password, LdapContextProcessor<T> contextProcessor) throws NamingException;

    <T> T executeLdapQuery(String userName, String password, LdapQuery ldapQuery, LdapSearchResultProcessor<T> resultProcessor) throws NamingException;

    interface LdapSearchResultProcessor<T> {

        T process(NamingEnumeration<SearchResult> searchResults) throws NamingException;
    }


    interface LdapContextProcessor<T> {

        T process(DirContext dirContext) throws NamingException;
    }
}
