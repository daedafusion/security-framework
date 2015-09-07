package com.daedafusion.security.admin;

import com.daedafusion.security.audit.AuditEvent;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.exceptions.UnauthorizedException;

import java.util.List;

/**
 * Created by mphilpot on 8/12/14.
 */
public interface AuditAdmin
{
    List<AuditEvent> getEvents(Subject subject, long after, long before, int limit) throws UnauthorizedException;
    List<AuditEvent> getEventsByUsername(Subject subject, long after, long before, String username, int limit) throws UnauthorizedException;
    List<AuditEvent> getEventsBySource(Subject subject, long after, long before, String source, int limit) throws UnauthorizedException;
}
