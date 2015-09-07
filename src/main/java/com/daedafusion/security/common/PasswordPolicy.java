package com.daedafusion.security.common;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 7/25/14.
 */
public class PasswordPolicy
{
    private static final Logger log = Logger.getLogger(PasswordPolicy.class);

    private Boolean enabled;
    private Boolean mustChange;
    private Boolean allowUserChange;
    private Boolean safeModify;
    private Long maxAge;
    private Long minAge;
    private Long graceExpiry;
    private Long expireWarning;
    private Integer minLength;
    private Integer maxLength;
    private Integer graceAuthnLimit;
    private TOTP	twoFactorAuthn;
    private PasswordQualityCheck qualityCheckLevel;

    public enum PasswordQualityCheck { DISABLED, RELAXED, STRICT}
    public enum TOTP {DISABLED, ENABLED, REQUIRED}
    
    public PasswordPolicy()
    {
    	this.enabled = false;
    	this.mustChange = false;
    	this.allowUserChange = true;
    	this.safeModify = false;
    	this.maxAge = 0L;
    	this.minAge = 0L;
    	this.graceExpiry = 0L;
    	this.expireWarning = 0L;
    	this.minLength = 0;
    	this.maxLength = 0;
    	this.graceAuthnLimit = 0;
    	this.twoFactorAuthn = TOTP.DISABLED;
    	this.qualityCheckLevel = PasswordQualityCheck.DISABLED;
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
     * getMinAge - Returns the minimum password age
     * 
     * @return	Number of seconds that must elapse between modifications to the password.
     */
    public Long getMinAge()
    {
    	return minAge;
    }
    
    /**
     * setMinAge - Set the minimum password age
     * 
     * @param minAge	Number of seconds that must elapse between modifications to the password
     */
    public void setMinAge(Long minAge)
    {
    	this.minAge = minAge;
    }
    
    /**
     * getMaxAge -	Returns the maximum password age before a password expires
     * 
     * @return		Number of seconds after which a modified password will expire.
     */
    public Long getMaxAge()
    {
        return maxAge;
    }

    /**
     * setMaxAge -	Sets the maximum password age before a password expires.
     * 				A value of 0 means the password does not expire.
     * 
     * @param maxAge	Number of seconds after which a modified password will expire.
     */
    public void setMaxAge(Long maxAge)
    {
        this.maxAge = maxAge;
    }

    /**
     * getQualityLevelCheck -	Returns an indication of the level of password 
     * 							quality check that will be verified when a password
     * 							is being modified.
     * @return
     */
    public PasswordQualityCheck getQualityCheckLevel()
    {
    	return qualityCheckLevel;
    }
    
    /**
     * setQualityCheckLevel -	Sets the level of password quality check to be performed
     * 							when a password is being modified.
     * @param checkLevel		DISABLED indicates that no quality check should be performed, 
     * 							RELAXED indicates that the quality check will be attempted but if
     * 							the server is unable to check, the password will be accepted, STRICT
     * 							indicates that the quality check will be attempted but if the server
     * 							is unable to verify, it will refuse the password.
     */
    public void setQualityCheckLevel(PasswordQualityCheck checkLevel )
    {
    	this.qualityCheckLevel = checkLevel;
    }
    
    /**
     * getMinLength -	Returns the minimum number of characters that must be
     * 					used in a password when password quality checking is enabled
     * 
     * @return		Number of characters
     */
    public Integer getMinLength()
    {
        return minLength;
    }

    /**
     * setMinLength -	Set the minimum number of characters that must be used
     * 					in a password when password quality checking is enabled
     * 
     * @param minLength		Minimum number of characters
     */
    public void setMinLength(Integer minLength)
    {
        this.minLength = minLength;
    }

    /**
     * getMaxLength -	Returns the maximum number of characters that must be
     * 					used in a password when password quality checking is enabled
     * 
     * @return		Number of characters
     */
    public Integer getMaxLength()
    {
        return maxLength;
    }

    /**
     * setMaxLength -	Set the maximum number of characters that must be used
     * 					in a password when password quality checking is enabled
     * 
     * @param maxLength		Maximum number of characters
     */
    public void setMaxLength(Integer maxLength)
    {
        this.maxLength = maxLength;
    }

    /**
     * getExpireWarning -	Returns the maximum number of seconds before a password
     * 						is due to expire that an expiration warning will be
     * 						returned to an authenticated user.
     * 
     * @return		Number of seconds
     */
    public Long getExpireWarning()
    {
        return expireWarning;
    }

    /**
     * setExpireWarning -	Sets the maximum number of seconds before a password
     * 						is due to expire that an expiration warning will be
     * 						returned to an authenticated user.  A value of 0 
     * 						indicates that no warning will be given.  The value
     * 						must be smaller than the value of the maximum password
     * 						age.
     * 
     * @param expireWarning		Number of seconds.
     */
    public void setExpireWarning(Long expireWarning)
    {
        this.expireWarning = expireWarning;
    }

    /**
     * getGraceAuthnLimit -	Returns the number of times an expired password can
     * 						be used to authenticate
     * 
     * @return	Number of times
     */
    public Integer getGraceAuthnLimit()
    {
    	return graceAuthnLimit;
    }
    
    /**
     * setGraceAuthnLimit -	Sets the maximum number of times an expired password
     * 						can be used to authenticate.  A value of 0 indicates
     * 						authentication with an expired password always fails.
     * 
     * @param limit		Maximum number of times authentication will be allowed
     */
    public void setGraceAuthnLimit( Integer limit)
    {
    	this.graceAuthnLimit = limit;
    }
    
    /**
     * getGraceExpiry -		Returns the number of seconds the grace authentications
     * 						are valid
     * 
     * @return		Number of seconds
     */
    public Long getGraceExpiry()
    {
    	return graceExpiry;
    }
    
    /**
     * setGraceExpiry -		Sets the number of seconds the grace authentications
     * 						are valid.  A value of 0 indicates that there is no
     * 						time limit on the grace authentications.
     * 
     * @param expiryPeriod	Number of seconds
     */
    public void setGraceExpiry( Long expiryPeriod )
    {
    	this.graceExpiry = expiryPeriod;
    }
    
    /**
     * getMustChange - 		Returns an indication as to whether users must 
     * 						change their passwords when they first bind to
     * 						the server after a password is set or reset by
     * 						a password administrator.
     * @return		FALSE indicates that users are not required to change their
     * 				passwords, TRUE indicates users are required to change
     * 				their passwords.
     */
    public Boolean getMustChange()
    {
    	return mustChange;
    }
    
    /**
     * setMustChange -		Sets an indication as to whether uses must change
     * 						their passwords when they first bind to 
     * 						the server after a password is set or reset by
     * 						a password administrator.
     * @param mustChange	FALSE indicates that users are not required to change their
     * 						passwords, TRUE indicates users are required to change
     * 						their passwords
     */
    public void setMustChange(Boolean mustChange)
    {
    	this.mustChange = mustChange;
    }
    
    /**
     * getAllowUserChange -	Returns an indication as to whether users can change
     * 						their own passwords.
     * 
     * @return		TRUE indicates users are permitted, FALSE indicates users are
     * 				not permitted
     */
    public Boolean getAllowUserChange()
    {
    	return allowUserChange;
    }
    
    /**
     * setAllowUserChange -	Sets an indicator as to whether users can change
     * 						their own passwords.
     * 
     * @param allowUserChange	True indicates users are permitted, False
     * 							indicates users are not permitted
     */
    public void setAllowUserChange( Boolean allowUserChange )
    {
    	this.allowUserChange = allowUserChange;
    }
    
    /**
     * getSafeModify -	Returns an indication as to whether or not the existing
     * 					password must be sent along with the new password when
     * 					being changed.
     * @return			True indicates the existing password must be sent along,
     * 					False indicates the existing password is not required
     */
    public Boolean getSafeModify()
    {
    	return safeModify;
    }
    
    /**
     * setSetModify -	Sets an indicator as to whether or not the existing 
     * 					password must be sent along with the new password when
     * 					being changed.
     * 					
     * @param safeModify	True indicates the existing password must be sent
     * 						along, False indicates the existing password is not
     * 						required
     */
    public void setSafeModify( Boolean safeModify)
    {
    	this.safeModify = safeModify;
    }
    
    /**
     * getTwoFactorAuthn -	Returns an indication of whether 2-factor authentication
     * 						is disabled, optional, or required
     * 
     * @return				True indicates that 2-factor authentication is required,
     * 						False indicates that it is optional
     */
    public TOTP getTwoFactorAuthn()
    {
        return twoFactorAuthn;
    }

    /** setTwoFactorAuthn -	Sets an indicators that 2-factor authentication is
     * 						disabled, required or optional.
     * 
     * @param twoFactorAuthn	DISABLED indicates that two-factor authentication is disabled, 
     * 							ENABLED indicates that two-factor authentication is enabled but
     * 							is not required, REQUIRED indicates that two-factor authentication
     * 							is enabled and required.
     */
    public void setTwoFactorAuthn(TOTP twoFactorAuthn)
    {
        this.twoFactorAuthn = twoFactorAuthn;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof PasswordPolicy)) return false;

        PasswordPolicy that = (PasswordPolicy) o;

        if (allowUserChange != null ? !allowUserChange.equals(that.allowUserChange) : that.allowUserChange != null)
            return false;
        if (enabled != null ? !enabled.equals(that.enabled) : that.enabled != null) return false;
        if (expireWarning != null ? !expireWarning.equals(that.expireWarning) : that.expireWarning != null)
            return false;
        if (graceAuthnLimit != null ? !graceAuthnLimit.equals(that.graceAuthnLimit) : that.graceAuthnLimit != null)
            return false;
        if (graceExpiry != null ? !graceExpiry.equals(that.graceExpiry) : that.graceExpiry != null) return false;
        if (maxAge != null ? !maxAge.equals(that.maxAge) : that.maxAge != null) return false;
        if (maxLength != null ? !maxLength.equals(that.maxLength) : that.maxLength != null) return false;
        if (minAge != null ? !minAge.equals(that.minAge) : that.minAge != null) return false;
        if (minLength != null ? !minLength.equals(that.minLength) : that.minLength != null) return false;
        if (mustChange != null ? !mustChange.equals(that.mustChange) : that.mustChange != null) return false;
        if (qualityCheckLevel != that.qualityCheckLevel) return false;
        if (safeModify != null ? !safeModify.equals(that.safeModify) : that.safeModify != null) return false;
        if (twoFactorAuthn != that.twoFactorAuthn) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = enabled != null ? enabled.hashCode() : 0;
        result = 31 * result + (mustChange != null ? mustChange.hashCode() : 0);
        result = 31 * result + (allowUserChange != null ? allowUserChange.hashCode() : 0);
        result = 31 * result + (safeModify != null ? safeModify.hashCode() : 0);
        result = 31 * result + (maxAge != null ? maxAge.hashCode() : 0);
        result = 31 * result + (minAge != null ? minAge.hashCode() : 0);
        result = 31 * result + (graceExpiry != null ? graceExpiry.hashCode() : 0);
        result = 31 * result + (expireWarning != null ? expireWarning.hashCode() : 0);
        result = 31 * result + (minLength != null ? minLength.hashCode() : 0);
        result = 31 * result + (maxLength != null ? maxLength.hashCode() : 0);
        result = 31 * result + (graceAuthnLimit != null ? graceAuthnLimit.hashCode() : 0);
        result = 31 * result + (twoFactorAuthn != null ? twoFactorAuthn.hashCode() : 0);
        result = 31 * result + (qualityCheckLevel != null ? qualityCheckLevel.hashCode() : 0);
        return result;
    }
}
