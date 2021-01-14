package com.daedafusion.security.admin;

import com.daedafusion.sf.ServiceRegistry;
import com.daedafusion.security.admin.impl.DomainAdminImpl;
import com.daedafusion.security.admin.providers.DomainAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.authorization.impl.UnanimousResultAuthorizationImpl;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.isA;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Created by mphilpot on 8/3/14.
 */
public class DomainAdminTest
{
    private static final Logger log = LogManager.getLogger(DomainAdminTest.class);

    ServiceRegistry mockRegistryPermit;
    ServiceRegistry mockRegistryDeny;
    DomainAdminProvider mockProvider;

    Domain df;

    @Before
    public void before()
    {
        mockRegistryPermit = mock(ServiceRegistry.class);
        mockRegistryDeny = mock(ServiceRegistry.class);
        Authorization mockAuthPermit = mock(UnanimousResultAuthorizationImpl.class);
        Authorization mockAuthDeny = mock(UnanimousResultAuthorizationImpl.class);

        when(mockRegistryPermit.getService(Authorization.class)).thenReturn(mockAuthPermit);

        when(mockAuthPermit.isAuthorized(isNull(Subject.class), isA(URI.class), isA(String.class), isA(Context.class))).thenReturn(true);

        when(mockRegistryDeny.getService(Authorization.class)).thenReturn(mockAuthDeny);

        when(mockAuthDeny.isAuthorized(isNull(Subject.class), isA(URI.class), isA(String.class), isA(Context.class))).thenReturn(false);

        mockProvider = mock(DomainAdminProvider.class);

        df = new Domain();
        df.setDomainName("daedafusion.com");
        df.setDescription("DaedaFusion, LLC");
        df.getAttributes().put("someKey", Collections.singleton("someValue"));
    }

    @Test
    public void serialization() throws IOException
    {
        ObjectMapper mapper = new ObjectMapper();

        String d = mapper.writeValueAsString(df);

        assertThat(d, is(notNullValue()));

        Domain dTest = mapper.readValue(d, Domain.class);

        assertThat(dTest.equals(df), is(true));
    }

    @Test
    public void createDomain() throws UnauthorizedException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryPermit);

        impl.getProviders().add(mockProvider);

        impl.createDomain(null, df);

        verify(mockProvider).createDomain(df);
    }

    @Test(expected = UnauthorizedException.class)
    public void createDomainUnauth() throws UnauthorizedException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);

        impl.getProviders().add(mockProvider);

        impl.createDomain(null, df);
    }

    @Test
    public void updateDomain() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryPermit);

        impl.getProviders().add(mockProvider);

        impl.updateDomain(null, df);

        verify(mockProvider).updateDomain(df);
    }

    @Test(expected = UnauthorizedException.class)
    public void updateDomainUnauth() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);

        impl.getProviders().add(mockProvider);

        impl.updateDomain(null, df);
    }

    @Test
    public void removeDomain() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryPermit);

        impl.getProviders().add(mockProvider);

        impl.removeDomain(null, "daedafusion.com");

        verify(mockProvider).removeDomain("daedafusion.com");
    }

    @Test(expected = UnauthorizedException.class)
    public void removeDomainUnauth() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);

        impl.getProviders().add(mockProvider);

        impl.removeDomain(null, "daedafusion.com");
    }

    @Test
    public void listDomains() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryPermit);

        impl.getProviders().add(mockProvider);

        impl.listDomains(null);

        verify(mockProvider).listDomains();
    }

    @Test(expected = UnauthorizedException.class)
    public void listDomainsUnauth() throws UnauthorizedException, NotFoundException
    {
        DomainAdminImpl impl = new DomainAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);

        impl.getProviders().add(mockProvider);

        impl.listDomains(null);
    }
}
