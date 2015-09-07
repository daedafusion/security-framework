package com.daedafusion.security.admin.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.common.Domain;
import com.daedafusion.security.exceptions.NotFoundException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface DomainAdminProvider extends Provider
{
    void createDomain(Domain domain);

    void updateDomain(Domain domain) throws NotFoundException;

    void removeDomain(String domain) throws NotFoundException;

    List<Domain> listDomains();
}
