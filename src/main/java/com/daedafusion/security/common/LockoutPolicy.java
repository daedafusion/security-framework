package com.daedafusion.security.common;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/25/14.
 */
public class LockoutPolicy
{
    private static final Logger log = Logger.getLogger(LockoutPolicy.class);

    private Boolean enabled;
    private Integer maxAttempts;
    private Integer passwordsInHistory;
    private Long duration;
    private Long failureCountInterval;
    private Long minDelay;
    private Long maxDelay;
    private Long maxIdle;

    public LockoutPolicy()
    {
    	this.enabled = false;
    	this.maxAttempts = 0;
    	this.passwordsInHistory = 0;
    	this.duration = 0L;
    	this.failureCountInterval = 0L;
    	this.minDelay = 0L;
    	this.maxDelay = 0L;
    	this.maxIdle = 0L;
    }

    /**
     * getPolicyEnabled - Returns an indication of whether the policy
     * 					  is enabled
     * 
     * @return	true if the policy is enabled, else false
     */
    public Boolean getPolicyEnabled()
    {
        return enabled;
    }

    /**
     * setPolicyEnabled - Enables or disables the enforcement of the policy
     * 
     * @param enabled	true if the policy is to be enabled, else false
     */
    public void setPolicyEnabled(Boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     * getFailureCountInterval -	Returns the number of seconds after which
     * 								the password failures are purged from the
     * 								failure counter, even though no successful
     * 								authentication occurred.
     * @return		Number of seconds
     */
    public Long getFailureCountInterval()
    {
    	return failureCountInterval;
    }
    
    /**
     * setFailureCountInterval -	Sets the number of seconds after which the
     * 								password failures are purged from the
     * 								failure counter, even though no successful
     * 								authentication occurred.  A value of 0 indicates
     * 								the failure counter is only reset as a result
     * 								of a successful authentication
     * 
     * @param failureCountInterval	Number of seconds
     */
    public void setFailureCountInterval( Long failureCountInterval )
    {
    	this.failureCountInterval = failureCountInterval;
    }
    
    /**
     * getMaxAttempts - Gets the maximum number of consecutive authentication
     * 					failures attempts before lockout
     * 
     * @return	Number of consecutive failure attempts
     */
    public Integer getMaxAttempts()
    {
        return maxAttempts;
    }

    /**
     * setMaxAttempts - Sets the maximum number of consecutive authentication
     * 					failure attempts before lockout
     * 
     * @param maxAttempts	Number of consecutive failure attempts
     */
    public void setMaxAttempts(Integer maxAttempts)
    {
        this.maxAttempts = maxAttempts;
    }

    /**
     * getLockoutDuration - Returns the lockout duration in seconds
     * 
     * @return 	Number of seconds that the password cannot be used to authenticate
     * 			due to too many failed authentication attempts
     */
    public Long getLockoutDuration()
    {
        return duration;
    }

    /**
     * setLockoutDuration - Sets the lockout duration in seconds
     * 
     * @param duration	Number of seconds that the password cannot be used to
     * 					authenticate due to too many failed authentication 
     * 					attempts
     */
    public void setLockoutDuration(Long duration)
    {
        this.duration = duration;
    }
    
    /**
     * getPasswordsInHistory -	Returns the maximum number of passwords
     * 							to keep in history
     * 
     * @return			Number of used passwords to store in history
     */
    public Integer getPasswordsInHistory()
    {
    	return passwordsInHistory;
    }
    
    /**
     * setPasswordsInHistory -	Sets the maximum number of used passwords
     * 							to keep in history
     * 
     * @param passwordsInHistory	Number of used passwords to key
     */
    public void setPasswordsInHistory( Integer passwordsInHistory )
    {
    	this.passwordsInHistory = passwordsInHistory;
    }
    
    /**
     * getMinDelay -	Returns the number of seconds to delay responding to the
     * 					first failed authentication attempt.
     * 
     * @return		Number of seconds
     */
    public Long getMinDelay()
    {
    	return minDelay;
    }
    
    /**
     * setMinDelay -	Sets the number of seconds to delay responding to the
     * 					first failed authentication attempt.  A value of 0
     * 					indicates no delays will be used.
     * 
     * @param delay		Number of seconds to delay
     */
    public void setMinDelay( Long delay)
    {
    	this.minDelay = delay;
    }
    
    /**
     * getMaxDelay -	Returns the maximum number of seconds to delay responding to
     * 					a failed authentication attempt.
     * 
     * @return		Number of seconds
     */
    public Long getMaxDelay()
    {
    	return maxDelay;
    }
    
    /**
     * setMaxDelay -	Sets the maximum number of seconds to delay responding to
     * 					a failed authentication attempt.  The time specified for
     * 					minimal dely is used as the start time and is then doubled
     * 					on each failure until the delay time is greater than or 
     * 					equal to the max delay or a successful authentication
     * 					occurs.  A minimum delay must be specified is a maximum
     * 					delay is specified.
     * 
     * @param delay		Number of seconds to delay
     */
    public void setMaxDelay( Long delay)
    {
    	this.maxDelay = delay;
    }
    /**
     * getMaxIdle -		Returns the number of seconds an account may remain unused
     * 					before it becomes locked.
     * 
     * @return			Number of seconds
     */
    public Long getMaxIdle()
    {
    	return maxIdle;
    }
    
    /**
     * setMaxIdle -		Sets the number of seconds an account may remain unused
     * 					before it becomes locked.  A value of 0 disables this check.
     * 
     * @param idlePeriod	Number of seconds
     */
    public void setMaxIdle( Long idlePeriod )
    {
    	this.maxIdle = idlePeriod;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof LockoutPolicy)) return false;

        LockoutPolicy that = (LockoutPolicy) o;

        if (duration != null ? !duration.equals(that.duration) : that.duration != null) return false;
        if (enabled != null ? !enabled.equals(that.enabled) : that.enabled != null) return false;
        if (failureCountInterval != null ? !failureCountInterval.equals(that.failureCountInterval) : that.failureCountInterval != null)
            return false;
        if (maxAttempts != null ? !maxAttempts.equals(that.maxAttempts) : that.maxAttempts != null) return false;
        if (maxDelay != null ? !maxDelay.equals(that.maxDelay) : that.maxDelay != null) return false;
        if (maxIdle != null ? !maxIdle.equals(that.maxIdle) : that.maxIdle != null) return false;
        if (minDelay != null ? !minDelay.equals(that.minDelay) : that.minDelay != null) return false;
        if (passwordsInHistory != null ? !passwordsInHistory.equals(that.passwordsInHistory) : that.passwordsInHistory != null)
            return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = enabled != null ? enabled.hashCode() : 0;
        result = 31 * result + (maxAttempts != null ? maxAttempts.hashCode() : 0);
        result = 31 * result + (passwordsInHistory != null ? passwordsInHistory.hashCode() : 0);
        result = 31 * result + (duration != null ? duration.hashCode() : 0);
        result = 31 * result + (failureCountInterval != null ? failureCountInterval.hashCode() : 0);
        result = 31 * result + (minDelay != null ? minDelay.hashCode() : 0);
        result = 31 * result + (maxDelay != null ? maxDelay.hashCode() : 0);
        result = 31 * result + (maxIdle != null ? maxIdle.hashCode() : 0);
        return result;
    }
}
