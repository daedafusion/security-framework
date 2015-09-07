package com.daedafusion.security.admin.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.admin.SessionAdmin;
import com.daedafusion.security.admin.providers.SessionAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Session;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import org.apache.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 7/21/14.
 */
public class SessionAdminImpl extends AbstractService<SessionAdminProvider> implements SessionAdmin
{
    private static final Logger log = Logger.getLogger(SessionAdminImpl.class);

    @Override
    public List<Session> getSessions(Subject subject) throws NotFoundException, UnauthorizedException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("session"), "GET", context))
        {
            return getSingleProvider().getSessions();
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public void expireSession(Subject subject, String id) throws UnauthorizedException, NotFoundException
    {
        Authorization auth = getServiceRegistry().getService(Authorization.class);

        Context context = new DefaultContext();

        if(auth.isAuthorized(subject, java.net.URI.create("session"), "DELETE", context))
        {
            getSingleProvider().expireSession(id);
        }
        else
        {
            throw new UnauthorizedException();
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return SessionAdminProvider.class;
    }
}
