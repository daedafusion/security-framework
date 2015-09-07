package com.daedafusion.security.audit;

/**
 * Created by mphilpot on 8/12/14.
 */
public interface Audit
{
    void reportEvent(AuditEvent event);
}
