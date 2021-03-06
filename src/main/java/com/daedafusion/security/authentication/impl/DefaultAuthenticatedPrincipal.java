package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Principal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.function.BooleanSupplier;

/**
 * Created by mphilpot on 7/15/14.
 */
public class DefaultAuthenticatedPrincipal extends AbstractPrincipal implements AuthenticatedPrincipal
{
    private static final Logger log = LogManager.getLogger(DefaultAuthenticatedPrincipal.class);

    private Set<Principal> associations;
    private Map<String, String> context;
    private BooleanSupplier isValid;

    public DefaultAuthenticatedPrincipal(UUID instanceId, Type type,
                                         Map<String, Set<String>> attributes, String signature,
                                         BooleanSupplier isValid)
    {
        super(instanceId, type, attributes, signature);
        associations = new HashSet<>();
        context = new HashMap<>();
        this.isValid = isValid;
    }

    @Override
    public boolean hasAssociations()
    {
        return !associations.isEmpty();
    }

    @Override
    public Set<Principal> getAssociations(Type type)
    {
        Set<Principal> result = new HashSet<>();

        for(Principal p : associations)
        {
            if(p.getType().equals(type))
            {
                result.add(p);
            }
        }

        return result;
    }

    @Override
    public void addAssociation(Principal principal)
    {
        associations.add(principal);
    }

    @Override
    public void removeAssociation(Principal principal)
    {
        associations.remove(principal);
    }

    @Override
    public boolean hasContext()
    {
        return !context.isEmpty();
    }

    @Override
    public void addContext(String key, String value)
    {
        context.put(key, value);
    }

    @Override
    public void removeContext(String key)
    {
        context.remove(key);
    }

    @Override
    public Set<String> getContextKeys()
    {
        return context.keySet();
    }

    @Override
    public String getContext(String key)
    {
        return context.get(key);
    }

    @Override
    public boolean isValid()
    {
        return isValid.getAsBoolean();
    }
}
