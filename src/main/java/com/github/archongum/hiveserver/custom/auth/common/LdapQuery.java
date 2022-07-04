package com.github.archongum.hiveserver.custom.auth.common;

import java.util.Arrays;
import static java.util.Objects.requireNonNull;


public class LdapQuery {

    private final String searchBase;

    private final String searchFilter;

    private final String[] attributes;

    private LdapQuery(String searchBase, String searchFilter, String[] attributes) {
        this.searchBase = requireNonNull(searchBase, "searchBase is null");
        this.searchFilter = requireNonNull(searchFilter, "searchFilter is null");
        requireNonNull(attributes, "attributes is null");
        this.attributes = Arrays.copyOf(attributes, attributes.length);
    }

    public String getSearchBase() {
        return searchBase;
    }

    public String getSearchFilter() {
        return searchFilter;
    }

    public String[] getAttributes() {
        return attributes;
    }

    public static class LdapQueryBuilder {

        private String searchBase;

        private String searchFilter;

        private String[] attributes = new String[0];

        public LdapQueryBuilder withSearchBase(String searchBase) {
            this.searchBase = requireNonNull(searchBase, "searchBase is null");
            return this;
        }

        public LdapQueryBuilder withSearchFilter(String searchFilter) {
            this.searchFilter = requireNonNull(searchFilter, "searchFilter is null");
            return this;
        }

        public LdapQueryBuilder withAttributes(String... attributes) {
            this.attributes = requireNonNull(attributes, "attributes is null");
            return this;
        }

        public LdapQuery build() {
            return new LdapQuery(searchBase, searchFilter, attributes);
        }
    }
}
