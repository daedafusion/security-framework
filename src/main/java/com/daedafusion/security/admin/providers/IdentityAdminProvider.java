package com.daedafusion.security.admin.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.NotFoundException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface IdentityAdminProvider extends Provider
{
    Identity createIdentity(Identity identity);

    Identity updateIdentity(Identity identity) throws NotFoundException;

    void removeIdentity(String user, String domain) throws NotFoundException;

    List<Identity> listIdentitiesForDomain(String domain);

    List<Capability> listCapabilities();

    void addCapability(Capability capability);

    void updateCapability(Capability capability) throws NotFoundException;

    void deleteCapability(String capability) throws NotFoundException;
}
