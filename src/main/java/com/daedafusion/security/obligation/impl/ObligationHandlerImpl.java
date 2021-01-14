package com.daedafusion.security.obligation.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.security.obligation.ObligationHandler;
import com.daedafusion.security.obligation.providers.ObligationHandlerProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public class ObligationHandlerImpl extends AbstractService<ObligationHandlerProvider> implements ObligationHandler
{
    private static final Logger log = LogManager.getLogger(ObligationHandlerImpl.class);

    @Override
    public void handle(List<Obligation> obligations, Context context)
    {
        for(Obligation ob : obligations)
        {
            for(ObligationHandlerProvider ohp : getProviders())
            {
                if(ohp.canHandle(ob))
                {
                    ohp.handle(ob, context);
                }
            }
        }
    }

    @Override
    public void handle(Obligation obligation, Context context)
    {
        for(ObligationHandlerProvider ohp : getProviders())
        {
            if(ohp.canHandle(obligation))
            {
                ohp.handle(obligation, context);
            }
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return ObligationHandlerProvider.class;
    }
}
