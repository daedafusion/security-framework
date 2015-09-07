package com.daedafusion.security.authentication;

import java.util.HashSet;
import java.util.Set;

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
        for(AuthenticatedPrincipal ap : principals)
        {
            if(ap.hasAttributes())
            {
                return true;
            }
        }

        return false;
    }

    public Set<String> getAttributeNames()
    {
        Set<String> result = new HashSet<>();

        for(AuthenticatedPrincipal ap : principals)
        {
            result.addAll(ap.getAttributeNames());
        }

        return result;
    }

    public Set<String> getAttributes(String name)
    {
        for(AuthenticatedPrincipal ap : principals)
        {
            if(ap.getAttributeNames().contains(name))
            {
                return ap.getAttributes(name);
            }
        }

        return null;
    }
}
