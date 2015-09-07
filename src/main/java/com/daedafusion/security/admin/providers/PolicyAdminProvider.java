package com.daedafusion.security.admin.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.common.LockoutPolicy;
import com.daedafusion.security.common.PasswordPolicy;

/**
 * Created by mphilpot on 7/25/14.
 */
public interface PolicyAdminProvider extends Provider
{
    LockoutPolicy getLockoutPolicy(String domain);
    void setLockoutPolicy(String domain, LockoutPolicy policy);

    PasswordPolicy getPasswordPolicy(String domain);
    void setPasswordPolicy(String domain, PasswordPolicy policy);
}
