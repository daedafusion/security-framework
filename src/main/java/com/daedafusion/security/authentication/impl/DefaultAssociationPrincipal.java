package com.daedafusion.security.authentication.impl;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Created by mphilpot on 7/15/14.
 */
public class DefaultAssociationPrincipal extends AbstractPrincipal
{
    private static final Logger log = LogManager.getLogger(DefaultAssociationPrincipal.class);

    public DefaultAssociationPrincipal(UUID instanceId, Type type, Map<String, Set<String>> attributes, String signature)
    {
        super(instanceId, type, attributes, signature);
    }
}
