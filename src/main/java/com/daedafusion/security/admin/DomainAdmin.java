package com.daedafusion.security.admin;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface DomainAdmin
{
    void createDomain(Subject subject, Domain domain) throws UnauthorizedException;

    void updateDomain(Subject subject, Domain domain) throws UnauthorizedException, NotFoundException;

    void removeDomain(Subject subject, String domain) throws UnauthorizedException, NotFoundException;

    List<Domain> listDomains(Subject subject) throws UnauthorizedException;
}
