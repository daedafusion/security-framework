package com.daedafusion.security.authorization;

import com.daedafusion.security.common.Context;
import org.apache.log4j.Logger;

import java.net.URI;

/**
 * Created by mphilpot on 7/14/14.
 */
public class ResourceActionContext
{
    private static final Logger log = Logger.getLogger(ResourceActionContext.class);

    private URI resource;
    private String action;
    private Context context;

    public ResourceActionContext(URI resource, String action, Context context)
    {
        this.resource = resource;
        this.action = action;
        this.context = context;
    }

    public URI getResource()
    {
        return resource;
    }

    public String getAction()
    {
        return action;
    }

    public Context getContext()
    {
        return context;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof ResourceActionContext)) return false;

        ResourceActionContext that = (ResourceActionContext) o;

        if (action != null ? !action.equals(that.action) : that.action != null) return false;
        if (resource != null ? !resource.equals(that.resource) : that.resource != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = resource != null ? resource.hashCode() : 0;
        result = 31 * result + (action != null ? action.hashCode() : 0);
        return result;
    }
}
