package com.daedafusion.security.admin.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.admin.DomainAdmin;
import com.daedafusion.security.admin.providers.DomainAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class DomainAdminImpl extends AbstractService<DomainAdminProvider> implements DomainAdmin
{
    private static final Logger log = Logger.getLogger(DomainAdminImpl.class);

    @Override
    public void createDomain(Subject subject, Domain domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain.getDomainName()).build();

        if(auth.isAuthorized(subject, java.net.URI.create("domain"), "POST", context))
        {
            for(DomainAdminProvider dap : getProviders())
            {
                dap.createDomain(domain);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void updateDomain(Subject subject, Domain domain) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain.getDomainName()).build();

        if(auth.isAuthorized(subject, java.net.URI.create("domain"), "PUT", context))
        {
            for(DomainAdminProvider dap : getProviders())
            {
                dap.updateDomain(domain);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void removeDomain(Subject subject, String domain) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, java.net.URI.create("domain"), "DELETE", context))
        {
            for(DomainAdminProvider dap : getProviders())
            {
                dap.removeDomain(domain);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<Domain> listDomains(Subject subject) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().build();

        if(auth.isAuthorized(subject, java.net.URI.create("domain"), "GET", context))
        {
            List<Domain> result = new ArrayList<>();

            for(DomainAdminProvider dap : getProviders())
            {
                result.addAll(dap.listDomains());
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return DomainAdminProvider.class;
    }
}
