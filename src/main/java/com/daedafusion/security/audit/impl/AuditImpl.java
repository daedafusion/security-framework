package com.daedafusion.security.audit.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.audit.Audit;
import com.daedafusion.security.audit.AuditEvent;
import com.daedafusion.security.audit.providers.AuditProvider;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 8/12/14.
 */
public class AuditImpl extends AbstractService<AuditProvider> implements Audit
{
    private static final Logger log = Logger.getLogger(AuditImpl.class);

    @Override
    public void reportEvent(AuditEvent event)
    {
        for(AuditProvider ap : getProviders())
        {
            reportEvent(event);
        }
    }

    @Override
    public Class getProviderInterface()
    {
        return AuditProvider.class;
    }
}
