package com.daedafusion.security.common;

import org.apache.log4j.Logger;

import java.util.UUID;

/**
 * Created by mphilpot on 7/19/14.
 */
public class Session
{
    private static final Logger log = Logger.getLogger(Session.class);

    private String id;
    private String user;
    private String domain;
    private String token;
    private Long sessionStart;
    private Long lastActive;
    private Long sessionExpiration;

    public Session()
    {
        id = UUID.randomUUID().toString();
    }

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getUser()
    {
        return user;
    }

    public void setUser(String user)
    {
        this.user = user;
    }

    public String getDomain()
    {
        return domain;
    }

    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    public String getToken()
    {
        return token;
    }

    public void setToken(String token)
    {
        this.token = token;
    }

    public Long getSessionStart()
    {
        return sessionStart;
    }

    public void setSessionStart(Long sessionStart)
    {
        this.sessionStart = sessionStart;
    }

    public Long getLastActive()
    {
        return lastActive;
    }

    public void setLastActive(Long lastActive)
    {
        this.lastActive = lastActive;
    }

    public Long getSessionExpiration()
    {
        return sessionExpiration;
    }

    public void setSessionExpiration(Long sessionExpiration)
    {
        this.sessionExpiration = sessionExpiration;
    }
}
