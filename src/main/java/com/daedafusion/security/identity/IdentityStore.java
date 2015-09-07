package com.daedafusion.security.identity;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.UnauthorizedException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */

public interface IdentityStore
{
    Identity getIdentity(Subject subject);

    /**
     *
     * @param subject
     * @param username
     * @param domain if null, then username must be fully qualified
     * @return
     * @throws UnauthorizedException
     */
    Identity getIdentity(Subject subject, String username, String domain) throws UnauthorizedException;

    /**
     * TODO refactor for generic query
     *
     * @param subject
     * @param domain
     * @return
     * @throws UnauthorizedException
     */
    List<Identity> getIdentitiesForDomain(Subject subject, String domain) throws UnauthorizedException;

    void setPassword(Subject subject, String password);

    /**
     *
     * @param subject
     * @param username
     * @param domain if null, then username must be fully qualified
     * @param password
     * @throws UnauthorizedException
     */
    void setPassword(Subject subject, String username, String domain, String password) throws UnauthorizedException;
}
