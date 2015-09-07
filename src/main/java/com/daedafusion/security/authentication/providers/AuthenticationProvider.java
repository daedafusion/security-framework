package com.daedafusion.security.authentication.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.SharedAuthenticationState;
import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;

import java.util.UUID;

/**
 * Created by mphilpot on 7/16/14.
 */
public interface AuthenticationProvider extends Provider
{
    UUID initialize(SharedAuthenticationState state);

    boolean login(UUID id, CallbackHandler handler) throws AccountLockedException, PasswordResetRequiredException, PasswordQualityException;

    AuthenticatedPrincipal commit(UUID id);

    void logoff(AuthenticatedPrincipal principal);

    void abort(UUID id);

    boolean verify(AuthenticatedPrincipal principal);

    String getAuthority();
}
