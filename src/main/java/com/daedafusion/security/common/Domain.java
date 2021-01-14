package com.daedafusion.security.common;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Domain
{
    private static final Logger log = LogManager.getLogger(Domain.class);

    private String domain;
    private String description;
    private Map<String, Set<String>> attributes;
    
    public static final String ATTR_BUSINESS_CATEGORY = "businesscategory";	// RFC 2256 - Describes the kind of business
    public static final String ATTR_NAME = "o";								// RFC 2256 - Name of organization associated with the domain
    public static final String ATTR_DESCRIPTION = "description";			// RFC 2256 - Description of the organization
    public static final String ATTR_FAX = "fax";							// RFC 2256 - Telephone number of a facsimile (fax) machine
    public static final String ATTR_LOCALITY = "localityname";				// RFC 2256 - Name of locality, such as city, country
    public static final String ATTR_PHYSICAL_DELIVERY_OFFICE = "physicaldeliverofficename";
    public static final String ATTR_POSTAL_ADDRESS = "postaladdress";		// RFC 2256 - Postal address
    public static final String ATTR_POSTAL_CODE = "postalcode";				// RFC 2256 - Postal code (zip code in US)
    public static final String ATTR_PO_BOX = "postofficebox";				// RFC 2256 - Post office box
    public static final String ATTR_STATE_PROVINCE = "stateorprovincename";	// RFC 2256 - Full name of state or province
    public static final String ATTR_STREET = "street";						// RFC 2256 - Physical address of individual, such as an address for package delivery
    public static final String ATTR_TELEPHONE_NUMBER = "telephonenumber";	// RFC 2256 - Telephone number of individual, typically an office phone number



    public Domain()
    {
        attributes = new HashMap<>();
    }

    public Domain(String domainName, String description)
    {
        this();
        this.domain = domainName;
        this.description = description;
    }

    public String getDomainName()
    {
        return domain;
    }

    public void setDomainName(String domain)
    {
        this.domain = domain;
    }

    public String getDescription()
    {
        return description;
    }

    public void setDescription(String description)
    {
        this.description = description;
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
        if (!(o instanceof Domain)) return false;

        Domain domain1 = (Domain) o;

        if (attributes != null ? !attributes.equals(domain1.attributes) : domain1.attributes != null) return false;
        if (description != null ? !description.equals(domain1.description) : domain1.description != null) return false;
        if (domain != null ? !domain.equals(domain1.domain) : domain1.domain != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = domain != null ? domain.hashCode() : 0;
        result = 31 * result + (description != null ? description.hashCode() : 0);
        result = 31 * result + (attributes != null ? attributes.hashCode() : 0);
        return result;
    }
}
