package com.daedafusion.security.common;

import com.daedafusion.security.exceptions.IdentityMismatchException;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.apache.log4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by mphilpot on 7/19/14.
 */
public class Identity
{
    private static final Logger log = Logger.getLogger(Identity.class);

    // Required fields
    private String username;
    private String domain;
    private String identifier;
    private Map<String, Set<String>> attributes;

    public static final String ATTR_FULLNAME = "cn";							// RFC 2256 - commonName, typically a person's full name
    public static final String ATTR_FIRSTNAME = "givenname";					// RFC 2256 - givenName, typically a person's first name
    public static final String ATTR_LASTNAME = "sn";							// RFD 2256 - surName, typically a person's last name
    public static final String ATTR_BUSINESS_CATEGORY = "businesscategory";		// RFC 2256 - Describes the kind of business
    public static final String ATTR_DEPARTMENT = "departmentnumber";			// RFC 2798 - Code for department to which a person belongs
    public static final String ATTR_DESCRIPTION = "description";				// RFC 2256 - Description of the person or individual
    public static final String ATTR_DISPLAYNAME = "displayname";				// RFC 2798 - Preferred name to be used when displaying entries
    public static final String ATTR_FAX = "fax";								// RFC 2256 - Telephone number of a facsimile (fax) machine
    public static final String ATTR_HOME_PHONE = "homephone";					// RFC 1274 - Home telephone number
    public static final String ATTR_JPEG_PHOTO = "jpegphoto";					// RFC 2798 - Stores image of a person in JPEG file format
    public static final String ATTR_LOCALITY = "localityname";					// RFC 2256 - Name of locality, such as city, country
    public static final String ATTR_LABELED_URI = "labeleduri";					// RFC 2079 - URI associated with person, such as public LinkedIn profile
    public static final String ATTR_MAIL = "mail";								// RFC 1274 - electronic mail address associated with a person
    public static final String ATTR_MOBILE_PHONE = "mobile";					// RFC 1274 - mobile telephone number
    public static final String ATTTR_ORG_NAME = "o";							// RFC 2256 - Name of organization to which individual is a member
    public static final String ATTR_ORG_UNIT_NAME = "ou";						// RFC 2256 - Name of organizational unit to which individual is a member
    public static final String ATTR_PAGER = "pager";							// RFC 1274 - Pager telephone number
    public static final String ATTR_PHYSICAL_DELIVERY_OFFICE = "physicaldeliverofficename";
    public static final String ATTR_POSTAL_ADDRESS = "postaladdress";			// RFC 2256 - Postal address
    public static final String ATTR_POSTAL_CODE = "postalcode";					// RFC 2256 - Postal code (zip code in US)
    public static final String ATTR_PO_BOX = "postofficebox";					// RFC 2256 - Post office box
    public static final String ATTR_PREFERRED_LANGUAGE = "perferredlanguage";	// RFC 2798 - Preferred written or spoken language for a person
    public static final String ATTR_ROOM_NUMBER = "roomnumber";					// RFC 1274 - Room or office number
    public static final String ATTR_STATE_PROVINCE = "stateorprovincepame";		// RFC 2256 - Full name of state or province
    public static final String ATTR_STREET = "street";							// RFC 2256 - Physical address of individual, such as an address for package delivery
    public static final String ATTR_TELEPHONE_NUMBER = "telephonenumber";		// RFC 2256 - Telephone number of individual, typically an office phone number
    public static final String ATTR_TITLE = "title";							// RFC 2256 - Title, such as "Vice President", of an person in their organizational context
    public static final String ATTR_AUTHENTICATOR_KEY = "authenticatorkey";	// Key used in support of 2-Factor authentication
    public static final String ATTR_CAPABILITIES = "entitledcapabilities";	// Names of capabilities the person is entitled to hold
    public static final String ATTR_ACCNT_CREATION = "createtimestamp";		// RFC 2252 - Time when the account was created
    public static final String ATTR_PWD_CHANGE = "pwdchangedtime";			// Timestamp of when the password was last changed
    public static final String ATTR_ACCNT_LOCK = "pwdaccountlockedtime";		// Timestamp of when the account was locked
    public static final String ATTR_FAILURE_TIME = "pwdfailuretime";			// Timestamp of consecutive authentication failures
    public static final String ATTR_PWD_RESET = "pwdreset";					// Indicator that the password must be reset
    public static final String ATTR_LAST_SUCCESS = "pwdlastsuccess";			// Timestamp of last successful authentication
    public static final String ATTR_PWD_STARTTIME = "pwdstarttime";			// Timestamp of when the password becomes valid for authentication
    public static final String ATTR_PWD_ENDTIME = "pwdendtime";				// Timestamp of when the password become invalid for authentication

    
    public Identity()
    {
        attributes = new HashMap<>();
    }

    public Identity(String username)
    {
        this();
    }

    public Identity(String user, String domain)
    {
        this();
        this.username = user;
        this.domain = domain;
    }

    @JsonIgnore
    public String getDomainQualifiedUsername()
    {
        return String.format("%s@%s", username, domain);
    }

    public void merge(Identity id)
    {
        if(id.getUsername().equals(username) && id.getDomain().equals(domain))
        {
            for(Map.Entry<String, Set<String>> entry : id.getAttributes().entrySet())
            {
                if(attributes.containsKey(entry.getKey()))
                {
                    attributes.get(entry.getKey()).addAll(entry.getValue());
                }
                else
                {
                    attributes.put(entry.getKey(), entry.getValue());
                }
            }
        }
        else
        {
            throw new IdentityMismatchException(); // TODO add message
        }
    }

    public String getUsername()
    {
        return username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getDomain()
    {
        return domain;
    }

    public String getIdentifier()
    {
    	return identifier;
    }
    
    public void setIdentifier(String identifier)
    {
    	this.identifier = identifier;
    }
    
    public void setDomain(String domain)
    {
        this.domain = domain;
    }

    public Map<String, Set<String>> getAttributes()
    {
        return attributes;
    }

    public void setAttributes(Map<String, Set<String>> attributes)
    {
        this.attributes = attributes;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (!(o instanceof Identity)) return false;

        Identity identity = (Identity) o;

        if (domain != null ? !domain.equals(identity.domain) : identity.domain != null) return false;
        if (identifier != null ? !identifier.equals(identity.identifier) : identity.identifier != null) return false;
        if (username != null ? !username.equals(identity.username) : identity.username != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (domain != null ? domain.hashCode() : 0);
        result = 31 * result + (identifier != null ? identifier.hashCode() : 0);
        return result;
    }
}
