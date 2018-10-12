package com.daedafusion.security.authentication;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.providers.TokenExchangeProvider;
import org.apache.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by mphilpot on 7/15/14.
 */
public class TokenExchangeImpl extends AbstractService<TokenExchangeProvider> implements TokenExchange
{
    private static final Logger log = Logger.getLogger(TokenExchangeImpl.class);

    @Override
    public Subject exchange(Token... tokens)
    {
        Set<AuthenticatedPrincipal> aps = getAPs(Arrays.stream(tokens));

        if(!aps.isEmpty())
        {
            return new Subject(aps);
        }
        else
        {
            return null;
        }
    }

    @Override
    public Subject exchange(List<Token> tokens)
    {
        Set<AuthenticatedPrincipal> aps = getAPs(tokens.stream());

        if(!aps.isEmpty())
        {
            return new Subject(aps);
        }
        else
        {
            return null;
        }
    }

    private Set<AuthenticatedPrincipal> getAPs(Stream<Token> tokens)
    {
        return tokens
                .flatMap(token -> getProviders().stream().flatMap(tep -> tep.exchange(token).stream()))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    @Override
    public List<Token> exchange(Subject subject)
    {
        return subject.getPrincipals().stream()
                .flatMap(ap -> getProviders().stream().map(tep -> tep.exchange(ap)))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public boolean destroyToken(Token token)
    {
        return getProviders().stream().map(tep -> tep.destroyToken(token)).filter(Objects::nonNull).allMatch(b -> b);
    }

    @Override
    public Class getProviderInterface()
    {
        return TokenExchangeProvider.class;
    }
}
