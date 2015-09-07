package com.daedafusion.security.admin.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.admin.AuditAdmin;
import com.daedafusion.security.admin.providers.AuditAdminProvider;
import com.daedafusion.security.audit.AuditEvent;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class AuditAdminImpl extends AbstractService<AuditAdminProvider> implements AuditAdmin
{
    private static final Logger log = Logger.getLogger(AuditAdminImpl.class);

    @Override
    public List<AuditEvent> getEvents(Subject subject, long after, long before, int limit) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("audit"), "GET", context))
        {
            List<AuditEvent> result = new ArrayList<>();

            for(AuditAdminProvider aap: getProviders())
            {
                result.addAll(aap.getEvents(after, before, limit));
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<AuditEvent> getEventsByUsername(Subject subject, long after, long before, String username, int limit) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("username", username);

        if(auth.isAuthorized(subject, java.net.URI.create("audit"), "GET", context))
        {
            List<AuditEvent> result = new ArrayList<>();

            for(AuditAdminProvider aap: getProviders())
            {
                result.addAll(aap.getEventsByUsername(after, before, username, limit));
            }

            return result;
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public List<AuditEvent> getEventsBySource(Subject subject, long after, long before, String source, int limit) throws UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();
        context.addContext("source", source);

        if(auth.isAuthorized(subject, java.net.URI.create("audit"), "GET", context))
        {
            List<AuditEvent> result = new ArrayList<>();

            for(AuditAdminProvider aap: getProviders())
            {
                result.addAll(aap.getEventsBySource(after, before, source, limit));
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
        return AuditAdminProvider.class;
    }
}
