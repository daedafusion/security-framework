package com.daedafusion.security.admin;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Session;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface SessionAdmin
{
    List<Session> getSessions(Subject subject) throws NotFoundException, UnauthorizedException;

    void expireSession(Subject subject, String id) throws UnauthorizedException, NotFoundException;
}
