package com.daedafusion.security.authentication;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.providers.AuthenticationProvider;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.decision.Combiner;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.decision.impl.AtLeastOneResultCombiner;
import com.daedafusion.security.decision.impl.UnanimousResultCombiner;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.AuthenticationFailedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 7/16/14.
 */
public class AuthenticationImpl extends AbstractService<AuthenticationProvider> implements Authentication
{
    private static final Logger log = LogManager.getLogger(AuthenticationImpl.class);

    private String combinerType; // unanimous, atLeastOne

    public AuthenticationImpl()
    {
        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                combinerType = getProperty("combiner", "atLeastOne");
            }
        });
    }

    @Override
    public Subject login(CallbackHandler handler)
            throws AccountLockedException, PasswordResetRequiredException, PasswordQualityException, AuthenticationFailedException
    {
        SharedAuthenticationState state = new SharedAuthenticationState();

        Map<String, UUID> sessions = new ConcurrentHashMap<>();

        for(AuthenticationProvider ap : getProviders())
        {
            UUID session = ap.initialize(state);
            sessions.put(ap.getAuthority(), session);
        }

        Combiner<Decision> combiner = null;

        switch (combinerType)
        {
            case "unanimous":
                combiner = new UnanimousResultCombiner();
                break;
            case "atLeastOne":
                combiner = new AtLeastOneResultCombiner();
                break;
            default:
                throw new IllegalArgumentException(String.format("Unknown combiner %s", combinerType));

        }

        List<Decision> decisionList = new ArrayList<>();
        List<AuthenticationProvider> successfulProviders = new ArrayList<>();

        for(AuthenticationProvider ap : getProviders())
        {
            boolean result = ap.login(sessions.get(ap.getAuthority()), handler);

            Decision d = new Decision(ap.getAuthority());

            if(result)
            {
                d.setResult(Decision.Result.PERMIT);
                successfulProviders.add(ap);
            }
            else
            {
                d.setResult(Decision.Result.DENY);
            }

            decisionList.add(d);
        }

        Decision result = combiner.getCombinedResult(decisionList);

        if(result.getResult().equals(Decision.Result.PERMIT))
        {
            Set<AuthenticatedPrincipal> principals = new HashSet<>();
            for(AuthenticationProvider ap : successfulProviders)
            {
                principals.add(ap.commit(sessions.get(ap.getAuthority())));
            }

            return new Subject(principals);
        }
        else
        {
            for(AuthenticationProvider ap : getProviders())
            {
                ap.abort(sessions.get(ap.getAuthority()));
            }

            throw new AuthenticationFailedException("Authentication Failed");
        }
    }

    @Override
    public void logoff(Subject subject)
    {
        for(AuthenticationProvider ap : getProviders())
        {
            for(AuthenticatedPrincipal aprin : subject.getPrincipals())
            {
                if(ap.getAuthority().equals(aprin.getAuthority()))
                {
                    ap.logoff(aprin);
                }
            }
        }
    }

    @Override
    public boolean verify(Subject subject)
    {
        for(AuthenticationProvider ap : getProviders())
        {
            for(AuthenticatedPrincipal aprin : subject.getPrincipals())
            {
                if(ap.getAuthority().equals(aprin.getAuthority()) && !ap.verify(aprin))
                {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public Class getProviderInterface()
    {
        return AuthenticationProvider.class;
    }
}
