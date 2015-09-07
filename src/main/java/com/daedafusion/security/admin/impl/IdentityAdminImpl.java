package com.daedafusion.security.admin.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.admin.IdentityAdmin;
import com.daedafusion.security.admin.providers.IdentityAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by mphilpot on 7/21/14.
 */
public class IdentityAdminImpl extends AbstractService<IdentityAdminProvider> implements IdentityAdmin
{
    private static final Logger log = Logger.getLogger(IdentityAdminImpl.class);

    @Override
    public Identity createIdentity(Subject subject, Identity identity) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("domain", identity.getDomain());

        // TODO serialize identity and add it to context

        if(auth.isAuthorized(subject, java.net.URI.create("identity"), "POST", context))
        {
            Identity result = new Identity(identity.getUsername(), identity.getDomain());

            for(IdentityAdminProvider iap : getProviders())
            {
                Identity id = iap.createIdentity(identity);
                result.merge(id);
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public Identity updateIdentity(Subject subject, Identity identity) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("domain", identity.getDomain());

        // TODO serialize identity and add it to context

        if(auth.isAuthorized(subject, java.net.URI.create("identity"), "PUT", context))
        {
            Identity result = new Identity(identity.getUsername(), identity.getDomain());

            for(IdentityAdminProvider iap : getProviders())
            {
                Identity id = iap.updateIdentity(identity);
                result.merge(id);
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void removeIdentity(Subject subject, String user, String domain) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("domain", domain);

        // TODO serialize identity and add it to context

        if(auth.isAuthorized(subject, java.net.URI.create("identity"), "DELETE", context))
        {
            for(IdentityAdminProvider iap : getProviders())
            {
                iap.removeIdentity(user, domain);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<Identity> listIdentitiesForDomain(Subject subject, String domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("domain", domain);

        if(auth.isAuthorized(subject, java.net.URI.create("identity:domain"), "GET", context))
        {
            Map<String, Identity> map = new HashMap<>();

            for(IdentityAdminProvider iap : getProviders())
            {
                List<Identity> iapList = iap.listIdentitiesForDomain(domain);

                for(Identity id : iapList)
                {
                    String key = String.format("%s@%s", id.getUsername(), id.getDomain());
                    if(map.containsKey(key))
                    {
                        map.get(key).merge(id);
                    }
                    else
                    {
                        map.put(key, id);
                    }
                }
            }

            return new ArrayList<Identity>(map.values());
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<Capability> listCapabilities(Subject subject) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("identity:capability"), "GET", context))
        {
            List<Capability> result = new ArrayList<>();

            for(IdentityAdminProvider iap : getProviders())
            {
                result.addAll(iap.listCapabilities());
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void addCapability(Subject subject, Capability capability) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("identity:capability"), "POST", context))
        {
            for(IdentityAdminProvider iap : getProviders())
            {
                iap.addCapability(capability);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void updateCapability(Subject subject, Capability capability) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("identity:capability"), "PUT", context))
        {
            for(IdentityAdminProvider iap : getProviders())
            {
                iap.updateCapability(capability);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void deleteCapability(Subject subject, String capability) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("identity:capability"), "DELETE", context))
        {
            for(IdentityAdminProvider iap : getProviders())
            {
                iap.deleteCapability(capability);
            }
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return IdentityAdminProvider.class;
    }
}
