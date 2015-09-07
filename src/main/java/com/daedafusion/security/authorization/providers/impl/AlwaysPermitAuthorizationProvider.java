package com.daedafusion.security.authorization.providers.impl;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.ResourceActionContext;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.obligation.Obligation;
import org.apache.log4j.Logger;

import java.net.URI;
import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public class AlwaysPermitAuthorizationProvider extends AbstractProvider implements AuthorizationProvider
{
    private static final Logger log = Logger.getLogger(AlwaysPermitAuthorizationProvider.class);

    public AlwaysPermitAuthorizationProvider()
    {
        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {

            }

            @Override
            public void start()
            {

            }

            @Override
            public void stop()
            {

            }

            @Override
            public void teardown()
            {

            }
        });
    }

    @Override
    public Decision getAccessDecision(Subject subject, URI resource, String action, Context context)
    {
        Decision d = new Decision(AlwaysPermitAuthorizationProvider.class.getName());

        Obligation loggingObligation = new Obligation(URI.create("obligation:logging"), Obligation.Fulfillment.ON_PERMIT);

        d.getObligations().add(loggingObligation);

        d.setResult(Decision.Result.PERMIT);

        return d;
    }

    @Override
    public Decision[] getAccessDecisionSet(Subject subject, List<ResourceActionContext> resourceActionContext)
    {
        Decision[] result = new Decision[resourceActionContext.size()];

        for(int i = 0; i < result.length; i++)
        {
            Decision d = new Decision(AlwaysPermitAuthorizationProvider.class.getName());

            d.getObligations().add(new Obligation(URI.create("obligation:logging"), Obligation.Fulfillment.ON_PERMIT));

            d.setResult(Decision.Result.PERMIT);

            result[i] = d;
        }

        return result;
    }
}
