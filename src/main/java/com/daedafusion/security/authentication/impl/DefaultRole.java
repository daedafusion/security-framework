package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Role;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Created by mphilpot on 7/15/14.
 */
public class DefaultRole extends AbstractPrincipal implements Role
{
    private static final Logger log = LogManager.getLogger(DefaultRole.class);
    private final RoleType roleType;

    public DefaultRole(UUID instanceId, Type type, Map<String, Set<String>> attributes, RoleType roleType, String signature)
    {
        super(instanceId, type, attributes, signature);
        this.roleType = roleType;
    }

    @Override
    public RoleType getRoleType()
    {
        return roleType;
    }
}
