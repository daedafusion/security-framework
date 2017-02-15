package com.daedafusion.security.decision;

import com.daedafusion.security.decision.impl.UnanimousResultCombiner;
import com.daedafusion.security.obligation.Obligation;
import org.apache.log4j.Logger;
import org.junit.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by mphilpot on 8/3/14.
 */
public class CombinerTest
{
    private static final Logger log = Logger.getLogger(CombinerTest.class);

    @Test
    public void allPermit()
    {
        UnanimousResultCombiner combiner = new UnanimousResultCombiner();

        Decision d1 = new Decision(UUID.randomUUID().toString());
        d1.setResult(Decision.Result.PERMIT);
        d1.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_PERMIT));

        Decision d2 = new Decision(UUID.randomUUID().toString());
        d2.setResult(Decision.Result.PERMIT);
        d2.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_DENY));

        List<Decision> list = new ArrayList<>();

        list.add(d1);
        list.add(d2);

        Decision result = combiner.getCombinedResult(list);

        assertThat(result.getResult(), is(Decision.Result.PERMIT));
        assertThat(result.getObligations().size(), is(2));
    }

    @Test
    public void allDeny()
    {
        UnanimousResultCombiner combiner = new UnanimousResultCombiner();

        Decision d1 = new Decision(UUID.randomUUID().toString());
        d1.setResult(Decision.Result.DENY);
        d1.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_PERMIT));

        Decision d2 = new Decision(UUID.randomUUID().toString());
        d2.setResult(Decision.Result.DENY);
        d2.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_DENY));

        List<Decision> list = new ArrayList<>();

        list.add(d1);
        list.add(d2);

        Decision result = combiner.getCombinedResult(list);

        assertThat(result.getResult(), is(Decision.Result.DENY));
        assertThat(result.getObligations().size(), is(2));
    }

    @Test
    public void mix1()
    {
        UnanimousResultCombiner combiner = new UnanimousResultCombiner();

        Decision d1 = new Decision(UUID.randomUUID().toString());
        d1.setResult(Decision.Result.DENY);
        d1.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_PERMIT));

        Decision d2 = new Decision(UUID.randomUUID().toString());
        d2.setResult(Decision.Result.PERMIT);
        d2.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_DENY));

        List<Decision> list = new ArrayList<>();

        list.add(d1);
        list.add(d2);

        Decision result = combiner.getCombinedResult(list);

        assertThat(result.getResult(), is(Decision.Result.DENY));
        assertThat(result.getObligations().size(), is(2));
    }

    @Test
    public void mix2()
    {
        UnanimousResultCombiner combiner = new UnanimousResultCombiner();

        Decision d1 = new Decision(UUID.randomUUID().toString());
        d1.setResult(Decision.Result.PERMIT);
        d1.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_PERMIT));

        Decision d2 = new Decision(UUID.randomUUID().toString());
        d2.setResult(Decision.Result.DENY);
        d2.getObligations().add(new Obligation(URI.create("audit"), Obligation.Fulfillment.ON_DENY));

        List<Decision> list = new ArrayList<>();

        list.add(d1);
        list.add(d2);

        Decision result = combiner.getCombinedResult(list);

        assertThat(result.getResult(), is(Decision.Result.DENY));
        assertThat(result.getObligations().size(), is(2));
    }

    @Test
    public void allAbstain()
    {
        UnanimousResultCombiner combiner = new UnanimousResultCombiner();

        Decision d1 = new Decision(UUID.randomUUID().toString());
        d1.setResult(Decision.Result.ABSTAIN);

        Decision d2 = new Decision(UUID.randomUUID().toString());
        d2.setResult(Decision.Result.ABSTAIN);

        List<Decision> list = new ArrayList<>();

        list.add(d1);
        list.add(d2);

        Decision result = combiner.getCombinedResult(list);

        assertThat(result.getResult(), is(Decision.Result.DENY));
    }
}
