package com.daedafusion.security.bindings;

import com.daedafusion.configuration.Configuration;
import com.daedafusion.security.authentication.impl.ContextToken;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.TokenExchange;
import org.apache.log4j.Logger;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

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
            Optional<Cookie> cookieOpt = Arrays.stream(httpServletRequest.getCookies() != null ? httpServletRequest.getCookies() : new Cookie[]{})
                    .filter(c -> c.getName().equals("bearer")).findFirst();
            if(cookieOpt.isPresent())
            {
                authorizationToken = cookieOpt.get().getValue();
            }
            else
            {
                httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
        }

        try
        {
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            // Strip "Bearer " if present
            authorizationToken = authorizationToken.replaceAll("(?i)"+ Pattern.quote("Bearer "), "");

            // Catch common cases we don't want passed through to exchange
            if(authorizationToken.isEmpty() || authorizationToken.equals("null"))
            {
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            final ContextToken token = new ContextToken(authorizationToken);

            Collections.list((Enumeration<String>)httpServletRequest.getHeaderNames()).forEach(h -> {
                token.addContext(h, httpServletRequest.getHeader(h));
            });

            Subject subject = tokenExchange.exchange(token);

            if(subject == null)
            {
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            LocalSubjectStorage.set(subject);

            // Valid Subject -- execute request
            chain.doFilter(request, response);

            LocalSubjectStorage.unset();
        }
        catch (ServiceFrameworkException e)
        {
            log.error("Framework error", e);
            httpServletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void destroy()
    {

    }
}
