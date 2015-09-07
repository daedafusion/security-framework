package com.daedafusion.security.authentication;

import org.apache.log4j.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 7/16/14.
 */
public final class SharedAuthenticationState
{
    private static final Logger log = Logger.getLogger(SharedAuthenticationState.class);

    private final Map<String, Object> state;

    public SharedAuthenticationState()
    {
        state = new ConcurrentHashMap<>();
    }

    public void reset()
    {
        state.clear();
    }

    public void addState(String key, Object value)
    {
        state.put(key, value);
    }

    public Object getState(String key)
    {
        return state.get(key);
    }

    public boolean hasState(String key)
    {
        return state.containsKey(key);
    }
}
