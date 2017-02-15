package com.daedafusion.security.obligation;

import org.apache.log4j.Logger;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by mphilpot on 7/14/14.
 */
public class Obligation
{
    private static final Logger log = Logger.getLogger(Obligation.class);

    // Common Obligation Types
    public static final String LOGGING = "obligation:logging";
    public static final String AUDIT = "obligation:audit";

    public enum Fulfillment { ON_PERMIT, ON_DENY }

    private URI uri;
    private Fulfillment fulfillment;
    private Map<String, String> attributes;

    public Obligation(URI uri, Fulfillment fulfillment, Map<String, String> attributes)
    {
        this.uri = uri;
        this.fulfillment = fulfillment;
        this.attributes = attributes;
    }

    public Obligation(URI uri, Fulfillment fulfillment)
    {
        this(uri, fulfillment, new HashMap<String, String>());
    }

    public URI getUri()
    {
        return uri;
    }

    public void setUri(URI uri)
    {
        this.uri = uri;
    }

    public Fulfillment getFulfillment()
    {
        return fulfillment;
    }

    public void setFulfillment(Fulfillment fulfillment)
    {
        this.fulfillment = fulfillment;
    }

    public Map<String, String> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes)
    {
        this.attributes = attributes;
    }
}
