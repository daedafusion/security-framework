package com.daedafusion.security.authorization.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.authorization.ResourceActionContext;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.decision.impl.UnanimousResultCombiner;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.security.obligation.ObligationHandler;
import org.apache.log4j.Logger;

import java.net.URI;
import java.util.ArrayList;
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

        for (AuthorizationProvider provider : getProviders())
        {
            decisions.add(provider.getAccessDecision(subject, resource, action, context));
        }

        UnanimousResultCombiner<Decision> combiner = new UnanimousResultCombiner<>();

        Decision result = combiner.getCombinedResult(decisions);

        ObligationHandler handler = getServiceRegistry().getService(ObligationHandler.class);

        Context obContext = new DefaultContext();
        obContext.addContext("auth:resource", resource.toString());
        obContext.addContext("auth:action", action);

        for(String k : context.getKeys())
        {
            obContext.putContext(k, context.getContext(k));
        }

        if (result.getResult().equals(Decision.Result.PERMIT))
        {
            for (Obligation ob : result.getObligations())
            {
                if (ob.getFulfillment().equals(Obligation.Fulfillment.ON_PERMIT))
                {
                    handler.handle(ob, obContext);
                }
            }

            return true;
        }
        else
        {
            for (Obligation ob : result.getObligations())
            {
                if(ob.getFulfillment().equals(Obligation.Fulfillment.ON_DENY))
                {
                    handler.handle(ob, obContext);
                }
            }

            return false;
        }
    }

    @Override
    public boolean[] isAuthorized(Subject subject, List<ResourceActionContext> resourceActionContext)
    {
        boolean[] finalResult = new boolean[resourceActionContext.size()];

        Decision[][] decisionMatrix = new Decision[getProviders().size()][resourceActionContext.size()];

        Decision[] matrixResult = new Decision[getProviders().size()];

        ObligationHandler handler = getServiceRegistry().getService(ObligationHandler.class);

        for(int i = 0; i < getProviders().size(); i++)
        {
            Decision[] decisions = getProviders().get(i).getAccessDecisionSet(subject, resourceActionContext);

            decisionMatrix[i] = decisions;
        }

        for(int j = 0; j < resourceActionContext.size(); j++)
        {
            List<Decision> acrossProviders = new ArrayList<>();

            for (int i = 0; i < getProviders().size(); i++)
            {
                acrossProviders.add(decisionMatrix[i][j]);
            }

            UnanimousResultCombiner<Decision> combiner = new UnanimousResultCombiner<>();

            matrixResult[j] = combiner.getCombinedResult(acrossProviders);
        }

        for(int j = 0; j < resourceActionContext.size(); j++ )
        {
            handler.handle(matrixResult[j].getObligations(), resourceActionContext.get(j).getContext());

            if(matrixResult[j].getResult().equals(Decision.Result.PERMIT))
            {
                log.warn("Obligation Context needs to be fixed in multi-decision authorization");

                for(Obligation ob : matrixResult[j].getObligations())
                {
                    if(ob.getFulfillment().equals(Obligation.Fulfillment.ON_PERMIT))
                    {
                        handler.handle(ob, resourceActionContext.get(j).getContext());
                    }
                }

                finalResult[j] = true;
            }
            else
            {
                log.warn("Obligation Context needs to be fixed in multi-decision authorization");

                for(Obligation ob : matrixResult[j].getObligations())
                {
                    if(ob.getFulfillment().equals(Obligation.Fulfillment.ON_DENY))
                    {
                        handler.handle(ob, resourceActionContext.get(j).getContext());
                    }
                }

                finalResult[j] = false;
            }
        }

        return finalResult;
    }

    @Override
    public Class getProviderInterface()
    {
        return AuthorizationProvider.class;
    }
}
