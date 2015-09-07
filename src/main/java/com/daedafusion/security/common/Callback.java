package com.daedafusion.security.common;

/**
 * Created by mphilpot on 7/21/14.
 */
public interface Callback
{
    // Callback name registry
    final String USERNAME = "username";
    final String PASSWORD = "password";
    final String OLD_PASSWORD = "oldPassword";
    final String DOMAIN = "domain";
    final String X509 = "x509";

    String getName();

    String getValue();

    void setValue(String value);
}
