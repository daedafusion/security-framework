package com.daedafusion.security.identity.providers.impl;

import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.identity.providers.SubjectInspectorProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Assumes there is one AP in a subject.  If there happens to be multiple, it returns the first.
 */
public class SingleAPInspector extends AbstractProvider implements SubjectInspectorProvider
{
    private static final Logger log = LogManager.getLogger(SingleAPInspector.class);

    @Override
    public String getFullyQualifiedUsername(Subject subject)
    {
        return subject.getPrincipals().iterator().next().getDomainQualifiedName();
    }

    @Override
    public String getDomain(Subject subject)
    {
        return subject.getPrincipals().iterator().next().getDomain();
    }
}
