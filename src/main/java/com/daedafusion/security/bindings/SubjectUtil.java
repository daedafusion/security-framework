package com.daedafusion.security.bindings;

import com.daedafusion.security.authentication.Subject;
import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/14/14.
 */
public class SubjectUtil
{
    private static final Logger log = Logger.getLogger(SubjectUtil.class);

    private SubjectUtil(){}

    public static Subject getSubject()
    {
        return LocalSubjectStorage.get();
    }
}
