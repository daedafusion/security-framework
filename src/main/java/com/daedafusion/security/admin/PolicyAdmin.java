package com.daedafusion.security.admin;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;
import com.daedafusion.security.exceptions.UnauthorizedException;

/**
 * Created by mphilpot on 7/25/14.
 */
public interface PolicyAdmin
{
    LockoutPolicy getLockoutPolicy(Subject subject, String domain) throws UnauthorizedException;
    void setLockoutPolicy(Subject subject, String domain, LockoutPolicy policy) throws UnauthorizedException;

    PasswordPolicy getPasswordPolicy(Subject subject, String domain) throws UnauthorizedException;
    void setPasswordPolicy(Subject subject, String domain, PasswordPolicy policy) throws UnauthorizedException;
}
