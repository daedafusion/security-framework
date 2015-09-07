package com.daedafusion.security.authentication;

import com.daedafusion.security.common.CallbackHandler;
import com.daedafusion.security.exceptions.AccountLockedException;
import com.daedafusion.security.exceptions.AuthenticationFailedException;
import com.daedafusion.security.exceptions.PasswordQualityException;
import com.daedafusion.security.exceptions.PasswordResetRequiredException;

/**
 * Created by mphilpot on 7/16/14.
 */
public interface Authentication
{
    Subject login(CallbackHandler handler) throws AccountLockedException, PasswordResetRequiredException, PasswordQualityException, AuthenticationFailedException;

    void logoff(Subject subject);

    boolean verify(Subject subject);
}
