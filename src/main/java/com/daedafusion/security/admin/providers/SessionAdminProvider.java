package com.daedafusion.security.admin.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.common.Session;
import com.daedafusion.security.exceptions.NotFoundException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface SessionAdminProvider extends Provider
{
    List<Session> getSessions();

    void expireSession(String sessionId) throws NotFoundException;
}
