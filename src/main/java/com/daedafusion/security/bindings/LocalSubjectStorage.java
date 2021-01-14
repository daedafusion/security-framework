package com.daedafusion.security.bindings;

import com.daedafusion.security.authentication.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Created by mphilpot on 7/11/14.
 */
public class LocalSubjectStorage
{
    private static final Logger log = LogManager.getLogger(LocalSubjectStorage.class);

    public static final ThreadLocal<Subject> subjectThreadLocal = new ThreadLocal<>();

    private LocalSubjectStorage(){}

    public static void set(Subject subject)
    {
        subjectThreadLocal.set(subject);
    }

    public static void unset()
    {
        subjectThreadLocal.remove();
    }

    public static Subject get()
    {
        return subjectThreadLocal.get();
    }
}
