package com.daedafusion.security.authentication.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Token;

import java.util.List;

/**
 * Created by mphilpot on 7/15/14.
 */
public interface TokenExchangeProvider extends Provider
{
    /**
     *
     * @param token
     * @return List of authPrincipals for given token. Empty list if token is invalid
     */
    List<AuthenticatedPrincipal> exchange(Token token);

    /**
     *
     * @param ap
     * @return valid Token if ap was created by this provider, null otherwise
     */
    Token exchange(AuthenticatedPrincipal ap);

    /**
     *
     * @return string to identify this exchange provider
     */
    String getAuthority();

    /**
     *
     * @param token
     * @return true if token was destroyed and/or rendered invalid, false otherwise. Null if token wasn't valid
     */
    Boolean destroyToken(Token token);
}
