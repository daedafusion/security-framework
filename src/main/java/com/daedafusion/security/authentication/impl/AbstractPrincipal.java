package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Principal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

/**
 * Created by mphilpot on 7/15/14.
 */
public abstract class AbstractPrincipal implements Principal
{
    private static final Logger log = LogManager.getLogger(AbstractPrincipal.class);

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
        return attributes.getOrDefault(PRINCIPAL_NAME, Collections.emptySet()).stream().findFirst().orElse(null);
    }

    @Override
    public String getAuthority()
    {
        return attributes.getOrDefault(PRINCIPAL_AUTHORITY, Collections.emptySet()).stream().findFirst().orElse(null);
    }

    @Override
    public String getIdentifier()
    {
        return attributes.getOrDefault(PRINCIPAL_IDENTIFIER, Collections.emptySet()).stream().findFirst().orElse(null);
    }

    @Override
    public String getDomain()
    {
        return attributes.getOrDefault(PRINCIPAL_DOMAIN, Collections.emptySet()).stream().findFirst().orElse(null);
    }

    @Override
    public String getDomainQualifiedName()
    {
        return attributes.getOrDefault(PRINCIPAL_DOMAIN_QUALIFIED_NAME, Collections.emptySet()).stream().findFirst().orElse(null);
    }

    @Override
    public Long getCreationTime()
    {
        return Long.parseLong(attributes.getOrDefault(PRINCIPAL_CREATION_TIME, Collections.emptySet()).stream().findFirst().orElse(null));
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
        return attributes.getOrDefault(name, Collections.emptySet());
    }

    @Override
    public String getSignature()
    {
        return signature;
    }
}
