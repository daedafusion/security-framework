package com.daedafusion.security.common;

import java.util.List;
import java.util.Set;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface Context
{
    Set<String> getKeys();
    List<String> getContext(String key);
    void putContext(String key, List<String> values);

    void addContext(String key, String value);
}
