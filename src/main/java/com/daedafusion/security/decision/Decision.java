package com.daedafusion.security.decision;

import com.daedafusion.security.obligation.Obligation;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public class Decision
{
    private static final Logger log = Logger.getLogger(Decision.class);

    public enum Result { PERMIT, DENY, ABSTAIN }

    private String id;
    private List<Obligation> obligations;
    private Result result;

    public Decision(String id)
    {
        this(id, Result.DENY);
    }

    public Decision(String id, Result result)
    {
        this.id = id;
        this.result = result;
        this.obligations = new ArrayList<>();
    }

    public Decision(String id, List<Obligation> obligations)
    {
        this.id = id;
        this.obligations = obligations;
    }

    public Result getResult()
    {
        return result;
    }

    public void setResult(Result result)
    {
        this.result = result;
    }

    public List<Obligation> getObligations()
    {
        return obligations;
    }

    public void setObligations(List<Obligation> obligations)
    {
        this.obligations = obligations;
    }

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }
}
