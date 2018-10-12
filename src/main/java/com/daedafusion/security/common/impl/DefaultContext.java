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

    private DefaultContext(Builder builder)
    {
        this.context = builder.context;
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
            context.put(key, new ArrayList<>());
        }

        return context.get(key);
    }

    public void putContext(String key, List<String> values)
    {
        context.put(key, values);
    }

    public void addContext(String key, String value)
    {
        getContext(key).add(value);
    }

    @Override
    public String toString()
    {
        return "Context=" + context + '}';
    }

    public static DefaultContext.Builder builder() {
        return new DefaultContext.Builder();
    }

    public static class Builder
    {
        private Map<String, List<String>> context = new HashMap<>();

        private Builder()
        {
        }

        public final Builder addContext(String key, String value)
        {
            if(!this.context.containsKey(key))
            {
                context.put(key, new ArrayList<>());
            }
            this.context.get(key).add(value);
            return this;
        }

        public final Builder setContext(String key, List<String> values)
        {
            this.context.put(key, values);
            return this;
        }

        public DefaultContext build()
        {
            return new DefaultContext(this);
        }
    }
}
