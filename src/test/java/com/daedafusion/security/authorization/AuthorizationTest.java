package com.daedafusion.security.authorization;

import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.sf.ServiceRegistry;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.impl.UnanimousResultAuthorizationImpl;
import com.daedafusion.security.authorization.providers.AuthorizationProvider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.impl.DefaultContext;
import com.daedafusion.security.decision.Decision;
import com.daedafusion.security.obligation.Obligation;
import com.daedafusion.security.obligation.ObligationHandler;
import com.daedafusion.security.obligation.impl.ObligationHandlerImpl;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.UUID;

import static org.mockito.Matchers.isA;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Created by mphilpot on 8/3/14.
 */
public class AuthorizationTest
{
    private static final Logger log = Logger.getLogger(AuthorizationTest.class);

    ServiceRegistry       mockRegistry;
    AuthorizationProvider mockProvider;
    ObligationHandler     mockObHandler;

    @Before
    public void before()
    {
        mockRegistry = mock(ServiceRegistry.class);

        mockObHandler = mock(ObligationHandlerImpl.class);

        mockProvider = mock(AuthorizationProvider.class);

        when(mockRegistry.getService(ObligationHandler.class)).thenReturn(mockObHandler);

        Decision d = new Decision(UUID.randomUUID().toString());
        d.setResult(Decision.Result.PERMIT);

        Obligation ob = new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_PERMIT);

        d.getObligations().add(ob);

        when(mockProvider.getAccessDecision(isNull(Subject.class), isA(URI.class), isA(String.class), isA(Context.class))).thenReturn(d);
    }

    @Test
    public void singleAuth()
    {
        UnanimousResultAuthorizationImpl impl = new UnanimousResultAuthorizationImpl();
        impl.setServiceRegistry(mockRegistry);

        impl.getProviders().add(mockProvider);

        impl.getListeners().forEach(LifecycleListener::postStart);

        impl.isAuthorized(null, URI.create("resource"), "get", new DefaultContext("someKey", "someValue"));

        verify(mockObHandler).handle(isA(Obligation.class), isA(Context.class));
    }
}
