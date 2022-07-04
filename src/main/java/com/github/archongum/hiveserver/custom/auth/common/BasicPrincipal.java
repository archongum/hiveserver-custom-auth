package com.github.archongum.hiveserver.custom.auth.common;

import java.security.Principal;
import java.util.Objects;
import static java.util.Objects.requireNonNull;


public final class BasicPrincipal implements Principal {

    private final String name;

    public BasicPrincipal(String name) {
        this.name = requireNonNull(name, "name is null");
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        BasicPrincipal that = (BasicPrincipal) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
}
