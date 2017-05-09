package com.daedafusion.security.authentication;


import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Created by mphilpot on 7/11/14.
 */
public interface Token
{
    /**
     *
     * @return String serialized version of the token
     */
    String getTokenString();

    /**
     * Optional session context ("client-ip" for example)
     *
     * @return Map
     */
    default Map<String, String> getContext(){return new HashMap<>();}

    /**
     * Token's from AuthenticatedPrincipals will have an Authority
     *
     * @return optional string
     */
    default Optional<String> getAuthority(){return Optional.empty();}
}
