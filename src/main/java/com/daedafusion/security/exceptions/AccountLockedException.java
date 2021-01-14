package com.daedafusion.security.exceptions;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Created by mphilpot on 7/18/14.
 */
public class AccountLockedException extends Exception
{
    private static final Logger log = LogManager.getLogger(AccountLockedException.class);
}
