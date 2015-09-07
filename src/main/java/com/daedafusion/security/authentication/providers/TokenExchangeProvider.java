package com.daedafusion.security.authentication.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;

/**
 * Created by mphilpot on 7/15/14.
 */
public interface TokenExchangeProvider extends Provider
{
    boolean canExchange(Token token);

    AuthenticatedPrincipal exchange(Token token);
    Token exchange(Subject subject);

    boolean isValidToken(String tokenString);
    boolean isTokenValid(Token token);

    Token getToken(String tokenString);

    String getAuthority();

    void destroyToken(Token token);
}
