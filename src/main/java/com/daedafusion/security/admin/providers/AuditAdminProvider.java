package com.daedafusion.security.admin.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.audit.AuditEvent;

import java.util.List;

/**
 * Created by mphilpot on 8/12/14.
 */
public interface AuditAdminProvider extends Provider
{
    List<AuditEvent> getEvents(long after, long before, int limit);
    List<AuditEvent> getEventsByUsername(long after, long before, String username, int limit);
    List<AuditEvent> getEventsBySource(long after, long before, String source, int limit);
}
