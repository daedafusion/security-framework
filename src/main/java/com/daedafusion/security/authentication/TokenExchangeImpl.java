package com.daedafusion.security.authentication;

import com.daedafusion.sf.AbstractService;
import com.daedafusion.security.authentication.providers.TokenExchangeProvider;
import org.apache.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by mphilpot on 7/15/14.
 */
public class TokenExchangeImpl extends AbstractService<TokenExchangeProvider> implements TokenExchange
{
    private static final Logger log = Logger.getLogger(TokenExchangeImpl.class);

    @Override
    public Subject exchange(Token... tokens)
    {
        Set<AuthenticatedPrincipal> aps = Arrays.stream(tokens)
                .flatMap(token -> getProviders().stream().flatMap(tep -> tep.exchange(token).stream()))
                .collect(Collectors.toSet());

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
    public List<Token> exchange(Subject subject)
    {
        return subject.getPrincipals().stream()
                .flatMap(ap -> getProviders().stream().map(tep -> tep.exchange(ap)))
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
