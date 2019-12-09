package com.daedafusion.security.identity.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.daedafusion.security.identity.IdentityStore;
import com.daedafusion.security.identity.providers.IdentityStoreProvider;
import org.apache.log4j.Logger;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by mphilpot on 7/21/14.
 */
public class IdentityStoreImpl extends AbstractService<IdentityStoreProvider> implements IdentityStore
{
    private static final Logger log = Logger.getLogger(IdentityStoreImpl.class);

    @Override
    public Identity getIdentity(Subject subject)
    {
        Identity response = new Identity(subject.getAttributes(Principal.PRINCIPAL_NAME).iterator().next(),
                subject.getAttributes(Principal.PRINCIPAL_DOMAIN).iterator().next());

        for(IdentityStoreProvider isp : getProviders())
        {
            Identity id = isp.getIdentity(subject, response.getUsername(), response.getDomain());

            if(id != null)
            {
                response.merge(id);
            }
        }

        return response;
    }

    @Override
    public Identity getIdentity(Subject subject, String user, String domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        if(domain == null)
        {
            String[] elem = user.split("@");
            user = elem[0];
            domain = elem[1];
        }

        Context context = DefaultContext.builder()
                .addContext("user", user)
                .addContext("domain", domain)
                .build();

        if(auth.isAuthorized(subject, java.net.URI.create("identity"), "GET", context))
        {
            Identity response = new Identity(user, domain);

            for(IdentityStoreProvider isp : getProviders())
            {
                Identity id = isp.getIdentity(subject, user, domain);
                if(id != null)
                {
                    response.merge(id);
                }
            }

            return response;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<Identity> getIdentitiesForDomain(Subject subject, String domain) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = DefaultContext.builder().addContext("domain", domain).build();

        if(auth.isAuthorized(subject, URI.create("identity:domain"), "GET", context))
        {
            Map<String, Identity> map = new HashMap<>();

            for(IdentityStoreProvider isp : getProviders())
            {
                List<Identity> list = isp.getIdentitiesForDomain(subject, domain);

                for(Identity id : list)
                {
                    if(map.containsKey(id.getDomainQualifiedUsername()))
                    {
                        map.get(id.getDomainQualifiedUsername()).merge(id);
                    }
                    else
                    {
                        map.put(id.getDomainQualifiedUsername(), id);
                    }
                }
            }

            return new ArrayList(map.values());
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void setPassword(Subject subject, String password)
    {
        for(IdentityStoreProvider isp : getProviders())
        {
            isp.setPassword(subject, subject.getAttributes(Principal.PRINCIPAL_NAME).iterator().next(),
                    subject.getAttributes(Principal.PRINCIPAL_DOMAIN).iterator().next(),
                    password);
        }
    }

    @Override
    public void setPassword(Subject subject, String user, String domain, String password) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        if(domain == null)
        {
            String[] elem = user.split("@");
            user = elem[0];
            domain = elem[1];
        }

        Context context = DefaultContext.builder()
                .addContext("user", user)
                .addContext("domain", domain)
                .build();

        if(auth.isAuthorized(subject, java.net.URI.create("identity:password"), "PUT", context))
        {
            for(IdentityStoreProvider isp : getProviders())
            {
                isp.setPassword(
                        subject,
                        user,
                        domain,
                        password);
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
        return IdentityStoreProvider.class;
    }
}
