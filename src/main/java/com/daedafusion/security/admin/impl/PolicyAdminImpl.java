package com.daedafusion.security.admin.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.admin.PolicyAdmin;
import com.daedafusion.security.admin.providers.PolicyAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/25/14.
 */
public class PolicyAdminImpl extends AbstractService<PolicyAdminProvider> implements PolicyAdmin
{
    private static final Logger log = Logger.getLogger(PolicyAdminImpl.class);

    @Override
    public LockoutPolicy getLockoutPolicy(Subject subject, String domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, java.net.URI.create("policy:lockout"), "GET", context))
        {
            return getSingleProvider().getLockoutPolicy(domain);
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void setLockoutPolicy(Subject subject, String domain, LockoutPolicy policy) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, java.net.URI.create("policy:lockout"), "POST", context))
        {
            getSingleProvider().setLockoutPolicy(domain, policy);
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public PasswordPolicy getPasswordPolicy(Subject subject, String domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, java.net.URI.create("policy:password"), "GET", context))
        {
            return getSingleProvider().getPasswordPolicy(domain);
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void setPasswordPolicy(Subject subject, String domain, PasswordPolicy policy) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, java.net.URI.create("policy:password"), "POST", context))
        {
            getSingleProvider().setPasswordPolicy(domain, policy);
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return PolicyAdminProvider.class;
    }
}
