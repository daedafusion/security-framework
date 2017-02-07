package com.daedafusion.security.authentication;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Created by mphilpot on 7/11/14.
 */
public final class Subject
{
    private Set<AuthenticatedPrincipal> principals;

    protected Subject(Set<AuthenticatedPrincipal> authPrincipals)
    {
        this.principals = authPrincipals;
    }

    public Set<AuthenticatedPrincipal> getPrincipals()
    {
        return principals;
    }

    public boolean hasAttributes()
    {
        return principals.stream().anyMatch(AuthenticatedPrincipal::hasAssociations);
    }

    public Set<String> getAttributeNames()
    {
        return principals.stream().flatMap(ap -> ap.getAttributeNames().stream()).collect(Collectors.toSet());
    }

    public Set<String> getAttributes(String name)
    {
        return principals.stream().flatMap(ap -> ap.getAttributes(name).stream()).collect(Collectors.toSet());
    }

    public boolean isValid()
    {
        return principals.stream().allMatch(AuthenticatedPrincipal::isValid);
    }
}
