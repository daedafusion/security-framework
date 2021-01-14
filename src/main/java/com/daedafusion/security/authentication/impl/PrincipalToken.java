package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Token;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Optional;

/**
 * Created by mphilpot on 3/27/17.
 */
public class PrincipalToken implements Token
{
    private static final Logger log = LogManager.getLogger(PrincipalToken.class);

    private final String tokenString;
    private final String authority;

    public PrincipalToken(String tokenString, String authority)
    {
        this.tokenString = tokenString;
        this.authority = authority;
    }

    @Override
    public String getTokenString()
    {
        return tokenString;
    }

    @Override
    public Optional<String> getAuthority()
    {
        return Optional.of(authority);
    }
}
