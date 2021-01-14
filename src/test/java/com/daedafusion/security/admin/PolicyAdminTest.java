package com.daedafusion.security.admin;

import com.daedafusion.sf.ServiceRegistry;
import com.daedafusion.security.admin.impl.PolicyAdminImpl;
import com.daedafusion.security.admin.providers.PolicyAdminProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authorization.Authorization;
import com.daedafusion.security.authorization.impl.UnanimousResultAuthorizationImpl;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.isA;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by mphilpot on 8/21/14.
 */
public class PolicyAdminTest
{
    private static final Logger log = LogManager.getLogger(PolicyAdminTest.class);

    ServiceRegistry mockRegistryPermit;
    ServiceRegistry mockRegistryDeny;
    PolicyAdminProvider mockProvider;

    PasswordPolicy passwordPolicy;
    LockoutPolicy lockoutPolicy;

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

        mockProvider = mock(PolicyAdminProvider.class);

        passwordPolicy = new PasswordPolicy();
        passwordPolicy.setPolicyEnabled(true);

        lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setPolicyEnabled(true);

        when(mockProvider.getLockoutPolicy("test")).thenReturn(lockoutPolicy);
        when(mockProvider.getPasswordPolicy("test")).thenReturn(passwordPolicy);
    }

    @Test
    public void serialization() throws IOException
    {
        ObjectMapper mapper = new ObjectMapper();

        String pp = mapper.writeValueAsString(passwordPolicy);

        assertThat(pp, is(notNullValue()));

        PasswordPolicy ppTest = mapper.readValue(pp, PasswordPolicy.class);

        assertThat(ppTest.equals(passwordPolicy), is(true));

        String lp = mapper.writeValueAsString(lockoutPolicy);

        assertThat(lp, is(notNullValue()));

        LockoutPolicy lpTest = mapper.readValue(lp, LockoutPolicy.class);

        assertThat(lpTest.equals(lockoutPolicy), is(true));
    }

    @Test(expected = UnauthorizedException.class)
    public void deny1() throws UnauthorizedException
    {
        PolicyAdminImpl impl = new PolicyAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.getLockoutPolicy(null, "test");
    }

    @Test(expected = UnauthorizedException.class)
    public void deny2() throws UnauthorizedException
    {
        PolicyAdminImpl impl = new PolicyAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.getPasswordPolicy(null, "test");
    }

    @Test(expected = UnauthorizedException.class)
    public void deny3() throws UnauthorizedException
    {
        PolicyAdminImpl impl = new PolicyAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.setLockoutPolicy(null, "test", null);
    }

    @Test(expected = UnauthorizedException.class)
    public void deny4() throws UnauthorizedException
    {
        PolicyAdminImpl impl = new PolicyAdminImpl();
        impl.setServiceRegistry(mockRegistryDeny);
        impl.getProviders().add(mockProvider);

        impl.setPasswordPolicy(null, "test", null);
    }

    @Test
    public void permit() throws UnauthorizedException
    {
        PolicyAdminImpl impl = new PolicyAdminImpl();
        impl.setServiceRegistry(mockRegistryPermit);
        impl.getProviders().add(mockProvider);

        PasswordPolicy pp = impl.getPasswordPolicy(null, "test");

        assertThat(pp.equals(passwordPolicy), is(true));

        LockoutPolicy lp = impl.getLockoutPolicy(null, "test");

        assertThat(lp.equals(lockoutPolicy), is(true));
    }
}
