package com.daedafusion.security.authentication;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.security.authentication.impl.DefaultAssociationPrincipal;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.authentication.impl.DefaultRole;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import org.mockito.internal.util.collections.Sets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Created by mphilpot on 7/15/14.
 */
public class SubjectTest
{
    private static final Logger log = LogManager.getLogger(SubjectTest.class);

    @Test
    public void main() throws KeyMaterialException, IOException, CryptoException
    {
        // Can I build a subject?

        // Example : I have a user account (uid=bob,o=pets.com,dn=argos,dn=com)
        //
        // Bob is a member of the pets.com Organization
        // Bob is a member of "C-Level" group
        // Bob has the role of "Pet Groomer" (static)
        // Bob has the role of "Employee of the Month" (dynamic)

        // Create a subject for Bob as if it was done through token exchange

        KeyPair pair = KeyGenUtil.generateKeyPair();

        PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(pair);

        Map<String, Set<String>> orgAttributes = new HashMap<>();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        UUID uuid = UUID.randomUUID();

        baos.write(uuid.toString().getBytes());
        baos.write(Principal.Type.ORGANIZATION.toString().getBytes());
        TreeSet<String> sortedKeys = new TreeSet<>(orgAttributes.keySet());

        for(String key : sortedKeys)
        {
            baos.write(key.getBytes());

            // foreach
            //baos.write(orgAttributes.get(key).getBytes());
        }

        byte[] signature = crypto.sign(baos.toByteArray());

        Principal petsDotCom = new DefaultAssociationPrincipal(
                UUID.randomUUID(),
                Principal.Type.ORGANIZATION,
                orgAttributes,
                Hex.encodeHexString(signature));

        Map<String, Set<String>> groupAttributes = new HashMap<>();

        Principal cLevel = new DefaultAssociationPrincipal(
                UUID.randomUUID(),
                Principal.Type.GROUP,
                groupAttributes,
                Hex.encodeHexString(signature)
        );

        Map<String, Set<String>> groomerAttributes = new HashMap<>();

        Role groomer = new DefaultRole(
                UUID.randomUUID(),
                Principal.Type.ROLE,
                groomerAttributes,
                Role.RoleType.STATIC,
                Hex.encodeHexString(signature)
        );

        Map<String, Set<String>> eotmAttributes = new HashMap<>();

        Role eotm = new DefaultRole(
                UUID.randomUUID(),
                Principal.Type.ROLE,
                eotmAttributes,
                Role.RoleType.DYNAMIC,
                Hex.encodeHexString(signature)
        );

        Map<String, Set<String>> attributes = new HashMap<>();

        attributes.put(Principal.PRINCIPAL_AUTHORITY, Collections.singleton("framework://example/provider/"));
        attributes.put(Principal.PRINCIPAL_CREATION_TIME, Collections.singleton(Long.toString(System.currentTimeMillis())));
        attributes.put(Principal.PRINCIPAL_DOMAIN, Collections.singleton("pets.com"));
        attributes.put(Principal.PRINCIPAL_DOMAIN_QUALIFIED_NAME, Collections.singleton(String.format("%s@%s", "bob", "pets.com")));
        attributes.put(Principal.PRINCIPAL_IDENTIFIER, Collections.singleton("uid=bob,o=pets.com,dn=argos,dn=com"));
        attributes.put(Principal.PRINCIPAL_NAME, Collections.singleton("bob"));

        AuthenticatedPrincipal ap = new DefaultAuthenticatedPrincipal(
                UUID.randomUUID(),
                Principal.Type.ACCOUNT,
                attributes,
                Hex.encodeHexString(signature),
                () -> true
        );

        ap.addAssociation(petsDotCom);
        ap.addAssociation(cLevel);
        ap.addAssociation(groomer);
        ap.addAssociation(eotm);

        ap.addContext("", ""); // TODO

        Subject subject = new Subject(Collections.singleton(ap));

        assertThat(subject.isValid(), is(true));

        AuthenticatedPrincipal ap2 = new DefaultAuthenticatedPrincipal(
                UUID.randomUUID(),
                Principal.Type.ACCOUNT,
                attributes,
                Hex.encodeHexString(signature),
                () -> false
        );

        subject = new Subject(Sets.newSet(ap, ap2));

        assertThat(subject.isValid(), is(false));

        AuthenticatedPrincipal ap3 = new DefaultAuthenticatedPrincipal(
                UUID.randomUUID(),
                Principal.Type.ACCOUNT,
                attributes,
                Hex.encodeHexString(signature),
                () -> false
        );

        subject = new Subject(Sets.newSet(ap2, ap3));

        assertThat(subject.isValid(), is(false));
    }
}
