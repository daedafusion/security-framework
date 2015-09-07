package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Token;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/28/14.
 */
public class DefaultToken implements Token
{
    private static final Logger log = Logger.getLogger(DefaultToken.class);
    private final String tokenString;
    private final String authority;

    public DefaultToken(String authority, String tokenString)
    {
        this.authority = authority;
        this.tokenString = tokenString;
    }

    @Override
    public String getAuthority()
    {
        return authority;
    }

    @Override
    public String getTokenString()
    {
        return tokenString;
    }
}
