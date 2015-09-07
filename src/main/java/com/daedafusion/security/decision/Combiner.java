package com.daedafusion.security.decision;

import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface Combiner<D extends Decision>
{
    D getCombinedResult(List<D> decisions);
}
