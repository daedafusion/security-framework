package com.daedafusion.security.bindings;

import com.daedafusion.configuration.Configuration;
import com.daedafusion.security.authentication.Token;
import com.daedafusion.security.authentication.impl.ContextToken;
import com.daedafusion.sf.ServiceFramework;
import com.daedafusion.sf.ServiceFrameworkException;
import com.daedafusion.sf.ServiceFrameworkFactory;
import com.daedafusion.security.authentication.Subject;
import com.daedafusion.security.authentication.TokenExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Created by mphilpot on 7/11/14.
 */
public class AuthorizationTokenFilter implements Filter
{
    private static final Logger log = LogManager.getLogger(AuthorizationTokenFilter.class);

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

        List<String> authorizationTokens = Collections.list(httpServletRequest.getHeaders("Authorization"));

        if(authorizationTokens.isEmpty())
        {
            Optional<Cookie> cookieOpt = Arrays.stream(httpServletRequest.getCookies() != null ? httpServletRequest.getCookies() : new Cookie[]{})
                    .filter(c -> c.getName().equals("bearer")).findFirst();
            if(cookieOpt.isPresent())
            {
                authorizationTokens = Collections.singletonList(cookieOpt.get().getValue());
            }
        }

        if(authorizationTokens.isEmpty() && httpServletRequest.getParameter("authorization") != null)
        {
            authorizationTokens = Collections.singletonList(httpServletRequest.getParameter("authorization"));
        }

        if(authorizationTokens.isEmpty())
        {
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try
        {
            TokenExchange tokenExchange = framework.getService(TokenExchange.class);

            // Strip "Bearer " if present
            List<Token> contextTokens =  authorizationTokens.stream()
                    .map(token -> token.replaceAll("(?i)"+ Pattern.quote("Bearer "), ""))
                    .map(ContextToken::new)
                    .collect(Collectors.toList());

            contextTokens.forEach(contextToken -> {
                Collections.list((Enumeration<String>)httpServletRequest.getHeaderNames()).forEach(h -> {
                    ((ContextToken)contextToken).addContext(h, httpServletRequest.getHeader(h));
                });
            });

            Subject subject = tokenExchange.exchange(contextTokens);

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
