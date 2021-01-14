package com.daedafusion.security.authorization.providers.impl;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.sf.AbstractProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;

/**
 * Created by mphilpot on 7/14/14.
 */
public class AlwaysPermitAuthorizationProvider extends AbstractProvider implements AuthorizationProvider
{
    private static final Logger log = LogManager.getLogger(AlwaysPermitAuthorizationProvider.class);

    @Override
    public Decision getAccessDecision(Subject subject, URI resource, String action, Context context)
    {
        Decision d = new Decision(AlwaysPermitAuthorizationProvider.class.getName());

        Obligation loggingObligation = new Obligation(URI.create(Obligation.LOGGING), Obligation.Fulfillment.ON_PERMIT);

        d.getObligations().add(loggingObligation);

        d.setResult(Decision.Result.PERMIT);

        return d;
    }
}
