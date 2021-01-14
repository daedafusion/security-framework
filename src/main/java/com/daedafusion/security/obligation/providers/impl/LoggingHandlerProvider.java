package com.daedafusion.security.obligation.providers.impl;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.security.obligation.providers.ObligationHandlerProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Created by mphilpot on 7/14/14.
 */
public class LoggingHandlerProvider extends AbstractProvider implements ObligationHandlerProvider
{
    private static final Logger log = LogManager.getLogger(LoggingHandlerProvider.class);

    @Override
    public boolean canHandle(Obligation obligation)
    {
        return obligation.getUri().toString().equals("obligation:logging");
    }

    @Override
    public void handle(Obligation obligation, Context context)
    {
        if(obligation.getAttributes().containsKey("level"))
        {
            // log at some specified level
        }
        else
        {
            log.info(String.format("Logging Obligation :: %s %s %s",
                    obligation.getFulfillment(), obligation.getAttributes(), context));
        }
    }
}
