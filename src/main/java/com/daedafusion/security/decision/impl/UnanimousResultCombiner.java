package com.daedafusion.security.decision.impl;

import com.daedafusion.security.decision.Combiner;
import com.daedafusion.security.decision.Decision;
import org.apache.log4j.Logger;

import java.util.List;
import java.util.UUID;

/**
 * Created by mphilpot on 7/14/14.
 */
public class UnanimousResultCombiner<D extends Decision> implements Combiner
{
    private static final Logger log = Logger.getLogger(UnanimousResultCombiner.class);

    @Override
    public Decision getCombinedResult(List decisions)
    {
        Decision result = new Decision(UUID.randomUUID().toString());

        Decision.Result r = null;

        for (Object obj : decisions)
        {
            // TODO shouldn't need this cast
            Decision d = (Decision) obj;

            result.getObligations().addAll(d.getObligations());

            if(r == null)
            {
                r = d.getResult();
            }
            else if(d.getResult().equals(Decision.Result.DENY))
            {
                r = Decision.Result.DENY;
            }
        }

        result.setResult(r);

        return result;
    }
}
