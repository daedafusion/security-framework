package com.daedafusion.security.authentication;

import java.util.Set;
import java.util.UUID;

/**
 * Created by mphilpot on 7/12/14.
 */
public interface Principal
{
    // Attribute Registry
    final String PRINCIPAL_NAME = "principal:name"; // user or username
    final String PRINCIPAL_AUTHORITY = "principal:authority";
    final String PRINCIPAL_IDENTIFIER = "principal:identifier";
    final String PRINCIPAL_DOMAIN = "principal:domain";
    final String PRINCIPAL_DOMAIN_QUALIFIED_NAME = "principal:domain-qualified-name";
    final String PRINCIPAL_CREATION_TIME = "principal:creation-time";
    final String PRINCIPAL_TOKEN = "principal:token";

    enum Type { ACCOUNT, GROUP, ORGANIZATION, MACHINE, ROLE, ANONYMOUS }

    UUID getInstanceId();
    Type getType();
    String getSignature();

    String getName(); // user or username
    String getAuthority(); // provider URI
    String getIdentifier(); // full ldap?
    String getDomain();
    String getDomainQualifiedName(); // name@domain
    Long getCreationTime();

    boolean hasAttributes();
    Set<String> getAttributeNames();
    Set<String> getAttributes(String name);
}
