package com.daedafusion.security.obligation.providers;

import com.daedafusion.sf.Provider;
import com.daedafusion.security.common.Context;
import com.daedafusion.security.obligation.Obligation;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface ObligationHandlerProvider extends Provider
{
    boolean canHandle(Obligation obligation);

    void handle(Obligation obligation, Context context);

}
