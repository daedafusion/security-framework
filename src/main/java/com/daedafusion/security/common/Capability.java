package com.daedafusion.security.common;

import org.apache.log4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;


public class Capability
{
    private static final Logger log = Logger.getLogger(Capability.class);

    private String capability;
    private String description;
    private Map<String, Set<String>> attributes;
    
    public static final String ATTR_DESCRIPTION = "description";				// RFC 2256 - Short description of the capability
    

    public Capability()
    {
        attributes = new HashMap<>();
    }

    public Capability(String capability, String description)
    {
        this();
        this.capability = capability;
        this.description = description;
    }

    public String getCapabilityName()
    {
        return capability;
    }

    public void setCapabilityName(String capability)
    {
        this.capability = capability;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
    }

    public Map<String, Set<String>> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(Map<String, Set<String>> attributes)
    {
        this.attributes = attributes;
    }

}
