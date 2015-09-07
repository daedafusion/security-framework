package com.daedafusion.security.identity.impl;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.identity.SubjectInspector;
import com.daedafusion.security.identity.providers.SubjectInspectorProvider;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 8/27/14.
 */
public class SubjectInspectorImpl extends AbstractService<SubjectInspectorProvider> implements SubjectInspector
{
    private static final Logger log = Logger.getLogger(SubjectInspectorImpl.class);

    @Override
    public String getFullyQualifiedUsername(Subject subject)
    {
        return getSingleProvider().getFullyQualifiedUsername(subject);
    }

    @Override
    public String getDomain(Subject subject)
    {
        return getSingleProvider().getDomain(subject);
    }

    @Override
    public Class getProviderInterface()
    {
        return SubjectInspectorProvider.class;
    }
}
