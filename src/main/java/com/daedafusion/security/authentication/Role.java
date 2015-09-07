package com.daedafusion.security.authentication;

/**
 * Created by mphilpot on 7/15/14.
 */
public interface Role extends Principal
{
    enum RoleType { STATIC, DYNAMIC }

    RoleType getRoleType();
}
