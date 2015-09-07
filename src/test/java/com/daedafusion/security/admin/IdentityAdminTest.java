package com.daedafusion.security.admin;

import com.daedafusion.sf.ServiceRegistry;
import com.daedafusion.security.admin.impl.IdentityAdminImpl;
import com.daedafusion.security.admin.providers.IdentityAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.authorization.impl.UnanimousResultAuthorizationImpl;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by mphilpot on 8/21/14.
 */
public class IdentityAdminTest
{
    private static final Logger log = Logger.getLogger(IdentityAdminTest.class);

    ServiceRegistry       mockRegistryPermit;
    ServiceRegistry       mockRegistryDeny;
    IdentityAdminProvider mockProvider;

    Identity id;

    @Before
    public void before() throws NotFoundException
    {
        mockRegistryPermit = mock(ServiceRegistry.class);
        mockRegistryDeny = mock(ServiceRegistry.class);
        Authorization mockAuthPermit = mock(UnanimousResultAuthorizationImpl.class);
        Authorization mockAuthDeny = mock(UnanimousResultAuthorizationImpl.class);

        when(mockRegistryPermit.getService(Authorization.class)).thenReturn(mockAuthPermit);

        when(mockAuthPermit.isAuthorized(isNull(Subject.class), isA(URI.class), isA(String.class), isA(Context.class))).thenReturn(true);

        when(mockRegistryDeny.getService(Authorization.class)).thenReturn(mockAuthDeny);

        when(mockAuthDeny.isAuthorized(isNull(Subject.class), isA(URI.class), isA(String.class), isA(Context.class))).thenReturn(false);

        mockProvider = mock(IdentityAdminProvider.class);

        id = new Identity("test@test.com");
        id.setIdentifier("uid");
        id.getAttributes().put(Identity.ATTR_FULLNAME, Collections.singleton("John Smith"));
        id.getAttributes().put(Identity.ATTR_MAIL, Collections.singleton("js@test.com"));

        when(mockProvider.listCapabilities()).thenReturn(Collections.singletonList(new Capability("admin", "admin")));
        when(mockProvider.listIdentitiesForDomain("test.com")).thenReturn(Collections.singletonList(id));
        when(mockProvider.createIdentity(any(Identity.class))).thenReturn(id);
        when(mockProvider.updateIdentity(any(Identity.class))).thenReturn(id);
    }

    @Test
    public void serialization() throws IOException
    {
        ObjectMapper mapper = new ObjectMapper();

        String i = mapper.writeValueAsString(id);

        assertThat(i, is(notNullValue()));

        Identity iTest = mapper.readValue(i, Identity.class);

        assertThat(iTest.equals(id), is(true));
    }

    @Test(expected = UnauthorizedException.class)
    public void deny1() throws UnauthorizedException
    {
        IdentityAdminImpl impl = new IdentityAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.listCapabilities(null);
    }

    @Test(expected = UnauthorizedException.class)
    public void deny2() throws UnauthorizedException
    {
        IdentityAdminImpl impl = new IdentityAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.listIdentitiesForDomain(null, "test.com");
    }

    @Test(expected = UnauthorizedException.class)
    public void deny3() throws UnauthorizedException
    {
        IdentityAdminImpl impl = new IdentityAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.createIdentity(null, id);
    }

    @Test(expected = UnauthorizedException.class)
    public void deny4() throws UnauthorizedException, NotFoundException
    {
        IdentityAdminImpl impl = new IdentityAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.updateIdentity(null, id);
    }
}
