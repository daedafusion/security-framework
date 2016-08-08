package com.daedafusion.security.exceptions;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
public class AuthenticationFailedException extends Exception
{
    private static final Logger log = Logger.getLogger(AuthenticationFailedException.class);

    public AuthenticationFailedException(String msg)
    {
        super(msg);
    }
}
