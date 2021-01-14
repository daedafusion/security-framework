package com.daedafusion.security.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by mphilpot on 8/12/14.
 */
public class AuditEvent
{
    private static final Logger log = LogManager.getLogger(AuditEvent.class);

    public enum Severity { INFO, SUCCESS, FAILURE }

    private String username;
    private String source;
    private String category;
    private String eventId;
    private Severity            severity;
    private Map<String, String> parameters;
    private byte[]              data;

    public AuditEvent()
    {
        parameters = new HashMap<>();
    }

    public AuditEvent(String username, String source, String category, String eventId, Severity severity, Map<String, String> parameters, byte[] data)
    {
        this.username = username;
        this.source = source;
        this.category = category;
        this.eventId = eventId;
        this.severity = severity;
        this.parameters = parameters;
        this.data = data;
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getSource()
    {
        return source;
    }

    public void setSource(String source)
    {
        this.source = source;
    }

    public String getCategory()
    {
        return category;
    }

    public void setCategory(String category)
    {
        this.category = category;
    }

    public String getEventId()
    {
        return eventId;
    }

    public void setEventId(String eventId)
    {
        this.eventId = eventId;
    }

    public Severity getSeverity()
    {
        return severity;
    }

    public void setSeverity(Severity severity)
    {
        this.severity = severity;
    }

    public Map<String, String> getParameters()
    {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters)
    {
        this.parameters = parameters;
    }

    public byte[] getData()
    {
        return data;
    }

    public void setData(byte[] data)
    {
        this.data = data;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof AuditEvent)) return false;

        AuditEvent that = (AuditEvent) o;

        if (category != null ? !category.equals(that.category) : that.category != null) return false;
        if (!Arrays.equals(data, that.data)) return false;
        if (eventId != null ? !eventId.equals(that.eventId) : that.eventId != null) return false;
        if (parameters != null ? !parameters.equals(that.parameters) : that.parameters != null) return false;
        if (severity != that.severity) return false;
        if (source != null ? !source.equals(that.source) : that.source != null) return false;
        if (username != null ? !username.equals(that.username) : that.username != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (source != null ? source.hashCode() : 0);
        result = 31 * result + (category != null ? category.hashCode() : 0);
        result = 31 * result + (eventId != null ? eventId.hashCode() : 0);
        result = 31 * result + (severity != null ? severity.hashCode() : 0);
        result = 31 * result + (parameters != null ? parameters.hashCode() : 0);
        result = 31 * result + (data != null ? Arrays.hashCode(data) : 0);
        return result;
    }
}
