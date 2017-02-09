package com.daedafusion.security.authentication.impl;

import com.daedafusion.security.authentication.Token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by mphilpot on 2/7/17.
 */
public class ContextToken implements Token
{
    private final String token;
    private final Map<String, String> context;

    public ContextToken(String token)
    {
        this.token = token;
        context = new HashMap<>();
    }

    public ContextToken addContext(String key, String value)
    {
        context.put(key, value);
        return this;
    }

    @Override
    public String getTokenString()
    {
        return token;
    }

    @Override
    public Map<String, String> getContext()
    {
        return Collections.unmodifiableMap(context);
    }
}
