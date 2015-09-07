package com.daedafusion.security.identity;

import com.daedafusion.security.authentication.Subject;

/**
 * When multiple AuthenticatedPrincipals are contained in a subject, this service allows you to customize how
 * you determine what is the canonical representations of identity fields for use in other business logic
 */
public interface SubjectInspector
{
    String getFullyQualifiedUsername(Subject subject);
    String getDomain(Subject subject);
}
