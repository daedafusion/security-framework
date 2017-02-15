package com.daedafusion.security.decision;

import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface Combiner<Decision>
{
    Decision getCombinedResult(List<Decision> decisions);
}
