package com.daedafusion.security.authentication;

import java.util.Set;

/**
 * Created by mphilpot on 7/12/14.
 */
public interface AuthenticatedPrincipal extends Principal
{
    boolean hasAssociations();
    Set<Principal> getAssociations(Type type);
    void addAssociation(Principal principal);
    void removeAssociation(Principal principal);

    boolean hasContext();
    void addContext(String key, String value);
    void removeContext(String key);
    Set<String> getContextKeys();
    String getContext(String key);
}
