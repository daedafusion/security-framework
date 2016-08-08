package com.daedafusion.security.bindings;

import com.daedafusion.configuration.Configuration;
import com.daedafusion.security.exceptions.UnauthorizedException;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.TokenExchange;
import com.daedafusion.security.exceptions.InvalidTokenException;
import org.apache.log4j.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Created by mphilpot on 7/11/14.
 */
public class AuthorizationTokenFilter implements Filter
{
    private static final Logger log = Logger.getLogger(AuthorizationTokenFilter.class);

    private ServiceFramework framework;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        framework = ServiceFrameworkFactory.getInstance().getFramework(); // assume framework is already started
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        // Handle excludes
        String authorizationExcludes = Configuration.getInstance().getString("authorizationFilter.pathExclude", null);

        if(authorizationExcludes != null)
        {
            String[] paths = authorizationExcludes.split(":");

            String path = httpServletRequest.getRequestURI();

            for (String p : paths)
            {
                if (path.startsWith(p))
                {
                    log.debug(String.format("Request %s excluded from authorization", path));
                    chain.doFilter(request, response);
                    return;
                }
            }
        }

        String authorizationToken = httpServletRequest.getHeader("Authorization");

        if(authorizationToken == null)
        {
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try
        {
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            // Strip "Bearer " if present
            authorizationToken = authorizationToken.replaceAll("(?i)"+ Pattern.quote("Bearer "), "");

            Token token = tokenExchange.getToken(authorizationToken);
            Subject subject = tokenExchange.exchange(token);

            if(subject == null)
            {
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            LocalSubjectStorage.set(subject);

            // Valid Subject -- execute request
            chain.doFilter(request, response);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("Framework error", e);
            httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        catch (InvalidTokenException e)
        {
            log.error("Invalid Token", e);
            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
        }
    }

    @Override
    public void destroy()
    {

    }
}
