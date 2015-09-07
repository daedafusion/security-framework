package com.daedafusion.security.bindings;

import com.daedafusion.configuration.Configuration;
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
import java.io.IOException;

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

        // Handle excludes
        String authorizationExcludes = Configuration.getInstance().getString("authorizationFilter.pathExclude", "");
        String[] paths = authorizationExcludes.split(":");

        String path = httpServletRequest.getRequestURI();

        for(String p : paths)
        {
            if(path.startsWith(p))
            {
                chain.doFilter(request, response);
                return;
            }
        }

        String authorizationToken = httpServletRequest.getHeader("Authorization");

        try
        {
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            Token token = tokenExchange.getToken(authorizationToken);
            Subject subject = tokenExchange.exchange(token);

            if(subject == null)
            {
                throw new ServletException(String.format("Token (%s) did not map to subject", authorizationToken));
            }

            LocalSubjectStorage.set(subject);
        }
        catch (ServiceFrameworkException e)
        {
            log.error("Framework error", e);
            // TODO return 500 error
            throw new ServletException("Framework error");
        }
        catch (InvalidTokenException e)
        {
            log.error("Invalid Token", e);
            throw new ServletException("Invalid token");
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy()
    {

    }
}
