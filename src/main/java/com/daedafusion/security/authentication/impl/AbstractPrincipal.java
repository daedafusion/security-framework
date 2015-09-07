package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Principal;
import org.apache.log4j.Logger;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Created by mphilpot on 7/15/14.
 */
public abstract class AbstractPrincipal implements Principal
{
    private static final Logger log = Logger.getLogger(AbstractPrincipal.class);

    private final UUID instanceId;
    private final Type                type;
    private final Map<String, Set<String>> attributes;

    private final String signature;

    protected AbstractPrincipal(UUID instanceId, Type type, Map<String, Set<String>> attributes, String signature)
    {
        this.instanceId = instanceId;
        this.type = type;
        this.attributes = attributes;
        this.signature = signature;
    }

    @Override
    public UUID getInstanceId()
    {
        return instanceId;
    }

    @Override
    public Type getType()
    {
        return type;
    }

    @Override
    public String getName()
    {
        return attributes.get(PRINCIPAL_NAME).iterator().next();
    }

    @Override
    public String getAuthority()
    {
        return attributes.get(PRINCIPAL_AUTHORITY).iterator().next();
    }

    @Override
    public String getIdentifier()
    {
        return attributes.get(PRINCIPAL_IDENTIFIER).iterator().next();
    }

    @Override
    public String getDomain()
    {
        return attributes.get(PRINCIPAL_DOMAIN).iterator().next();
    }

    @Override
    public String getDomainQualifiedName()
    {
        return attributes.get(PRINCIPAL_DOMAIN_QUALIFIED_NAME).iterator().next();
    }

    @Override
    public long getCreationTime()
    {
        return Long.parseLong(attributes.get(PRINCIPAL_CREATION_TIME).iterator().next());
    }

    @Override
    public boolean hasAttributes()
    {
        return !attributes.isEmpty();
    }

    @Override
    public Set<String> getAttributeNames()
    {
        return attributes.keySet();
    }

    @Override
    public Set<String> getAttributes(String name)
    {
        return attributes.get(name);
    }

    @Override
    public String getSignature()
    {
        return signature;
    }
}
