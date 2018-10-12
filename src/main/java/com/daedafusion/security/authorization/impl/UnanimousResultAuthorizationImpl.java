package com.daedafusion.security.authorization.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.decision.impl.UnanimousResultCombiner;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.security.obligation.ObligationHandler;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public class UnanimousResultAuthorizationImpl extends AbstractService<AuthorizationProvider> implements Authorization
{
    private static final Logger log = Logger.getLogger(UnanimousResultAuthorizationImpl.class);

    @Override
    public boolean isAuthorized(Subject subject, URI resource, String action, Context context)
    {
        List<Decision> decisions = new ArrayList<>();

        for(AuthorizationProvider provider : getProviders())
        {
            decisions.add(provider.getAccessDecision(subject, resource, action, context));
        }

        UnanimousResultCombiner combiner = new UnanimousResultCombiner();
        Decision combinedResult = combiner.getCombinedResult(decisions);

        ObligationHandler handler = getServiceRegistry().getService(ObligationHandler.class);


        DefaultContext.Builder builder = DefaultContext.builder()
                .addContext("auth:resource", resource.toString())
                .addContext("auth:action", action);

        context.getKeys().forEach(key -> builder.setContext(key, context.getContext(key)));
        Context obligationContext = builder.build();

        if(combinedResult.getResult().equals(Decision.Result.PERMIT))
        {
            combinedResult.getObligations().stream().filter(ob -> ob.getFulfillment().equals(Obligation.Fulfillment.ON_PERMIT))
                    .forEach(ob -> handler.handle(ob, obligationContext));

            return true;
        }
        else
        {
            combinedResult.getObligations().stream().filter(ob -> ob.getFulfillment().equals(Obligation.Fulfillment.ON_DENY))
                    .forEach(ob -> handler.handle(ob, obligationContext));

            return false;
        }
    }

    @Override
    public boolean isAuthorized(Subject subject, HttpServletRequest request, Context context)
    {
        URI uri = URI.create(request.getRequestURI());
        String action = request.getMethod();

        DefaultContext.Builder builder = DefaultContext.builder();
        context.getKeys().forEach(key -> context.getContext(key).forEach(value -> builder.addContext(key, value)));
        Collections.list((Enumeration<String>)request.getHeaderNames()).forEach(key -> builder.addContext(key, request.getHeader(key)));

        Context updatedContext = builder.build();

        return isAuthorized(subject, uri, action, updatedContext);
    }

    @Override
    public Class getProviderInterface()
    {
        return AuthorizationProvider.class;
    }
}
