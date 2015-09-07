package com.daedafusion.security.authentication;

import com.daedafusion.security.exceptions.InvalidTokenException;

/**
 * Created by mphilpot on 7/11/14.
 */
public interface TokenExchange
{
    Subject exchange(Token token);
    Token exchange(Subject subject);

    Token getToken(String tokenString) throws InvalidTokenException;

    boolean isTokenValid(Token token);

    void destroyToken(Token token);
}
