package com.daedafusion.security.obligation;

import com.daedafusion.security.common.Context;

import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface ObligationHandler
{
    void handle(List<Obligation> obligations, Context context);

    void handle(Obligation obligation, Context context);
}
