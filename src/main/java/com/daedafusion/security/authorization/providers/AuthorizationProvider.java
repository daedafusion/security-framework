package com.daedafusion.security.authorization.providers;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.sf.Provider;

import java.net.URI;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface AuthorizationProvider extends Provider
{
    Decision getAccessDecision(Subject subject, URI resource, String action, Context context);
}
