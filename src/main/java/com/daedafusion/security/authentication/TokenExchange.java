package com.daedafusion.security.authentication;

import java.util.List;

/**
 * Created by mphilpot on 7/11/14.
 */
public interface TokenExchange
{
    /**
     *
     * @param tokens array of tokens
     * @return valid subject if the exchange could be performed, null otherwise
     */
    Subject exchange(Token... tokens);
    Subject exchange(List<Token> tokens);

    /**
     *
     * @param subject
     * @return Token list
     */
    List<Token> exchange(Subject subject);

    /**
     *
     * @param token
     * @return true if successful, false otherwise
     */
    boolean destroyToken(Token token);
}
