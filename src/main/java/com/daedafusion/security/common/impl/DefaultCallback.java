package com.daedafusion.security.common.impl;

import com.daedafusion.security.common.Callback;
import org.apache.log4j.Logger;


/**
 * Created by patrick on 7/22/14.
 */
public class DefaultCallback implements Callback
{
    private static final Logger log = Logger.getLogger(DefaultCallback.class);
    private String name;
    private String value;

    public DefaultCallback(String callbackName)
    {
        this.name = callbackName;
    }


    @Override
    public String getName()
    {
        return this.name;
    }

    @Override
    public String getValue()
    {
        return this.value;
    }

    @Override
    public void setValue(String value)
    {
        this.value = value;
    }
}