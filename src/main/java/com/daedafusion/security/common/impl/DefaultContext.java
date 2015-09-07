package com.daedafusion.security.common.impl;

import com.daedafusion.security.common.Context;
import org.apache.log4j.Logger;

import java.util.*;

/**
 * Created by mphilpot on 7/14/14.
 */
public class DefaultContext implements Context
{
    private static final Logger log = Logger.getLogger(DefaultContext.class);

    private Map<String, List<String>> context;

    public DefaultContext()
    {
        context = new HashMap<>();
    }

    public DefaultContext(String key, String value)
    {
        this();
        context.put(key, Collections.singletonList(value));
    }

    @Override
    public Set<String> getKeys()
    {
        return context.keySet();
    }

    @Override
    public List<String> getContext(String key)
    {
        if(!context.containsKey(key))
        {
            context.put(key, new ArrayList<String>());
        }

        return context.get(key);
    }

    @Override
    public void putContext(String key, List<String> values)
    {
        context.put(key, values);
    }

    @Override
    public void addContext(String key, String value)
    {
        getContext(key).add(value);
    }

    @Override
    public String toString()
    {
        return "Context=" + context + '}';
    }
}
