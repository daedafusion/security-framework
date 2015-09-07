package com.daedafusion.security.identity.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Identity;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface IdentityStoreProvider extends Provider
{
    /**
     *
     * @param username
     * @param domain if null, then username must be fully qualified
     * @return
     */
    Identity getIdentity(Subject subject, String username, String domain);

    List<Identity> getIdentitiesForDomain(Subject subject, String domain);

    /**
     *
     * @param username
     * @param domain if null, then username must be fully qualified
     * @param password
     */
    void setPassword(Subject subject, String username, String domain, String password);

    String getAuthority();
}
