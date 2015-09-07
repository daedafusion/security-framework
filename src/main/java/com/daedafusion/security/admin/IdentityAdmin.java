package com.daedafusion.security.admin;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Capability;
import com.daedafusion.security.common.Identity;
import com.daedafusion.security.exceptions.NotFoundException;
import com.daedafusion.security.exceptions.UnauthorizedException;

import java.util.List;

/**
 * Created by mphilpot on 7/19/14.
 */
public interface IdentityAdmin
{
    Identity createIdentity(Subject subject, Identity identity) throws UnauthorizedException;

    Identity updateIdentity(Subject subject, Identity identity) throws UnauthorizedException, NotFoundException;

    void removeIdentity(Subject subject, String user, String domain) throws UnauthorizedException, NotFoundException;

    List<Identity> listIdentitiesForDomain(Subject subject, String domain) throws UnauthorizedException;

    List<Capability> listCapabilities(Subject subject) throws UnauthorizedException;

    void addCapability(Subject subject, Capability capability) throws UnauthorizedException;

    void updateCapability(Subject subject, Capability capability) throws UnauthorizedException, NotFoundException;

    void deleteCapability(Subject subject, String capability) throws UnauthorizedException, NotFoundException;
}
