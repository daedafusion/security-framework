package com.daedafusion.security.authentication;

/**
 * Created by mphilpot on 7/11/14.
 */
public interface Token
{
    String getAuthority();

    String getTokenString();
}
