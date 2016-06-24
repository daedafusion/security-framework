package com.daedafusion.security.authorization.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.ResourceActionContext;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.decision.Decision;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface AuthorizationProvider extends Provider
{
    Decision getAccessDecision(Subject subject, URI resource, String action, Context context);

    Decision getAccessDecision(Subject subject, HttpServletRequest request, Context context);

    Decision[] getAccessDecisionSet(Subject subject, List<ResourceActionContext> resourceActionContext);
}
