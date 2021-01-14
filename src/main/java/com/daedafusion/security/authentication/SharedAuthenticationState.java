package com.daedafusion.security.authentication;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 7/16/14.
 */
public final class SharedAuthenticationState
{
    private static final Logger log = LogManager.getLogger(SharedAuthenticationState.class);

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

    @SuppressWarnings("unchecked")
    public <T> T getState(String key)
    {
        return (T) state.get(key);
    }

    public boolean hasState(String key)
    {
        return state.containsKey(key);
    }
}
