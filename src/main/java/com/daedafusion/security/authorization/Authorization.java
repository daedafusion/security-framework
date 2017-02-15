package com.daedafusion.security.authorization;

import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.common.Context;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.List;

/**
 * Created by mphilpot on 7/14/14.
 */
public interface Authorization
{
    boolean isAuthorized(Subject subject, URI resource, String action, Context context);

    boolean isAuthorized(Subject subject, HttpServletRequest request, Context context);
}
