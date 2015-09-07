package com.daedafusion.security.authentication.providers;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.CryptoFactory;
import com.daedafusion.crypto.PublicCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.sf.AbstractProvider;
import com.daedafusion.sf.LifecycleListener;
import com.daedafusion.security.authentication.AuthenticatedPrincipal;
import com.daedafusion.security.authentication.Principal;
import com.daedafusion.security.authentication.SharedAuthenticationState;
import com.daedafusion.security.authentication.impl.DefaultAuthenticatedPrincipal;
import com.daedafusion.security.common.Callback;
import com.daedafusion.security.common.CallbackHandler;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by mphilpot on 7/16/14.
 */
public class ExampleAuthenticationProvider extends AbstractProvider implements AuthenticationProvider
{
    private static final Logger log = Logger.getLogger(ExampleAuthenticationProvider.class);

    private Map<UUID, SharedAuthenticationState> sessions;
    private KeyPair keyPair;

    public ExampleAuthenticationProvider()
    {
        addLifecycleListener(new LifecycleListener()
        {
            @Override
            public void init()
            {
                sessions = new ConcurrentHashMap<UUID, SharedAuthenticationState>();
                try
                {
                    keyPair = KeyGenUtil.generateKeyPair();
                }
                catch (KeyMaterialException e)
                {
                    log.error("", e);
                }
            }

            @Override
            public void start()
            {

            }

            @Override
            public void stop()
            {

            }

            @Override
            public void teardown()
            {

            }
        });
    }

    @Override
    public UUID initialize(SharedAuthenticationState state)
    {
        UUID sessionId = UUID.randomUUID();
        sessions.put(sessionId, state);

        return sessionId;
    }

    @Override
    public boolean login(UUID id, CallbackHandler handler)
    {
        SharedAuthenticationState state = sessions.get(id);

        List<Callback> callbacks = new ArrayList<>();

        callbacks.add(new Callback()
        {
            @Override
            public String getName()
            {
                return Callback.USERNAME;
            }

            @Override
            public String getValue()
            {
                return "mphilpot";
            }

            @Override
            public void setValue(String value)
            {

            }
        });
        callbacks.add(new Callback()
        {
            @Override
            public String getName()
            {
                return Callback.PASSWORD;
            }

            @Override
            public String getValue()
            {
                return null;
            }

            @Override
            public void setValue(String value)
            {

            }
        });
        callbacks.add(new Callback()
        {
            @Override
            public String getName()
            {
                return Callback.DOMAIN;
            }

            @Override
            public String getValue()
            {
                return "domain";
            }

            @Override
            public void setValue(String value)
            {

            }
        });

        handler.handle(callbacks.toArray(new Callback[0]));

        for(Callback cb : callbacks)
        {
            if(cb.getName().equals(Callback.USERNAME))
            {
                state.addState(Callback.USERNAME, cb.getValue());
            }
            else if(cb.getName().equals(Callback.PASSWORD))
            {
                state.addState(Callback.PASSWORD, cb.getValue());
            }
            else if(cb.getName().equals(Callback.DOMAIN))
            {
                state.addState(Callback.DOMAIN, cb.getValue());
            }
        }

        // Make call to identity provider
        String token = "token";

        //token = identityProvider.authenticate(state.getState(..)...)

        // retrun false on failure

        Map<String, String> attributes = new HashMap<>();

        // attributes = identityProvider.getUser(...)

        //attributes.put(Principal.PRINCIPAL_TOKEN, token);

        state.addState("attributes", attributes);

        return true;
    }

    @Override
    public AuthenticatedPrincipal commit(UUID id)
    {
        SharedAuthenticationState state = sessions.get(id);

        PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

        Map<String, Set<String>> attributes = (Map<String, Set<String>>) state.getState("attributes");

        String signature = null;

        // Sign principal
        UUID instanceId = UUID.randomUUID();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try
        {
            baos.write(instanceId.toString().getBytes());
            baos.write(Principal.Type.ACCOUNT.toString().getBytes());

            TreeSet<String> sortedKeys = new TreeSet<>(attributes.keySet());

            for(String key : sortedKeys)
            {
                baos.write(key.getBytes());

                // For each in set
                //baos.write(attributes.get(key).getBytes());
            }

            byte[] sig = crypto.sign(baos.toByteArray());

            signature = Hex.encodeHexString(sig);
        }
        catch (IOException | CryptoException e)
        {
            log.error("", e);
        }

        AuthenticatedPrincipal principal = new DefaultAuthenticatedPrincipal(
                instanceId,
                Principal.Type.ACCOUNT,
                attributes,
                signature
        );

        // Add associations or context

        sessions.remove(id);

        return principal;
    }

    @Override
    public void logoff(AuthenticatedPrincipal principal)
    {
        //String token = principal.getAttributes(Principal.PRINCIPAL_TOKEN);

        //identityProvider.logoff(token)
    }

    @Override
    public void abort(UUID id)
    {
        sessions.remove(id);
    }

    @Override
    public boolean verify(AuthenticatedPrincipal principal)
    {
        try
        {
            byte[] sig = Hex.decodeHex(principal.getSignature().toCharArray());

            PublicCrypto crypto = CryptoFactory.getInstance().getPublicCrypto(keyPair);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            baos.write(principal.getInstanceId().toString().getBytes());
            baos.write(principal.getType().toString().getBytes());

            TreeSet<String> sortedKeys = new TreeSet<>(principal.getAttributeNames());

            for(String key : sortedKeys)
            {
                baos.write(key.getBytes());
                // for each in set
                //baos.write(principal.getAttributes(key).getBytes());
            }

            return crypto.verify(sig, baos.toByteArray());
        }
        catch (DecoderException | CryptoException | IOException e)
        {
            log.error("", e);
        }

        return false;
    }

    @Override
    public String getAuthority()
    {
        return ExampleAuthenticationProvider.class.getName();
    }
}
