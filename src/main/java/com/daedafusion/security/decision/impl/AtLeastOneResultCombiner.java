package com.daedafusion.security.decision.impl;

import com.daedafusion.security.decision.Combiner;
import com.daedafusion.security.decision.Decision;
import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Created by mphilpot on 7/14/14.
 */
public class AtLeastOneResultCombiner implements Combiner<Decision>
{
    private static final Logger log = Logger.getLogger(AtLeastOneResultCombiner.class);

    @Override
    public Decision getCombinedResult(List<Decision> decisions)
    {
        Decision result = new Decision(UUID.randomUUID().toString());

        List<Decision.Result> intermediateResults = new ArrayList<>();

        decisions.forEach(d -> {
            result.getObligations().addAll(d.getObligations());
            intermediateResults.add(d.getResult());
        });

        // Filter abstain
        if(intermediateResults.stream().filter(r -> !r.equals(Decision.Result.ABSTAIN)).anyMatch(r -> r.equals(Decision.Result.PERMIT)))
        {
            result.setResult(Decision.Result.PERMIT);
        }
        else
        {
            result.setResult(Decision.Result.DENY);
        }

        return result;
    }
}
