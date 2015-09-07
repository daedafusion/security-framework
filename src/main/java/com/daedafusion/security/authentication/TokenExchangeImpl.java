package com.daedafusion.security.authentication;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.providers.TokenExchangeProvider;
import com.daedafusion.security.exceptions.InvalidTokenException;
import org.apache.log4j.Logger;

import java.util.Collections;

/**
 * Created by mphilpot on 7/15/14.
 */
public class TokenExchangeImpl extends AbstractService<TokenExchangeProvider> implements TokenExchange
{
    private static final Logger log = Logger.getLogger(TokenExchangeImpl.class);

    @Override
    public Subject exchange(Token token)
    {
        for(TokenExchangeProvider tep : getProviders())
        {
            if(tep.canExchange(token))
            {
                AuthenticatedPrincipal ap = tep.exchange(token);

                return new Subject(Collections.singleton(ap));
            }
        }

        return null;
    }

    @Override
    public Token exchange(Subject subject)
    {
        // This is broken with multiple principals!!  TODO
        for(TokenExchangeProvider tep : getProviders())
        {
            Token token = tep.exchange(subject);

            if(token != null)
            {
                return token;
            }
        }

        return null;
    }

    @Override
    public Token getToken(String tokenString) throws InvalidTokenException
    {
        for(TokenExchangeProvider tep : getProviders())
        {
            Token token = tep.getToken(tokenString);

            if(token != null)
            {
                return token;
            }
        }

        throw new InvalidTokenException();
    }

    @Override
    public boolean isTokenValid(Token token)
    {
        for(TokenExchangeProvider tep : getProviders())
        {
            if(token.getAuthority().equals(tep.getAuthority()))
            {
                return tep.isTokenValid(token);
            }
        }

        return false;
    }

    @Override
    public void destroyToken(Token token)
    {
        for(TokenExchangeProvider tep : getProviders())
        {
            if(token.getAuthority().equals(tep.getAuthority()))
            {
                tep.destroyToken(token);
            }
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return TokenExchangeProvider.class;
    }
}
