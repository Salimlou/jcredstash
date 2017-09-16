package com.jessecoyle;

import org.hamcrest.Matchers;
import org.junit.Assume;
import org.junit.ClassRule;
import org.junit.rules.TestRule;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 * Created by jcoyle on 2/1/16.
 */
public class JavaxCryptoTest extends CredStashCryptoTest {

    @ClassRule
    public static TestRule assumption = (statement, description) -> {
        try {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            Assume.assumeThat("Unlimited Strength policy files installed", maxAllowedKeyLength, Matchers.greaterThanOrEqualTo(256));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return statement;
    };

    public JavaxCryptoTest(String name, String key, String digestKey, String decrypted, String encrypted, String digest) {
        super(name, key, digestKey, decrypted, encrypted, digest);
    }

    @Override
    protected CredStashCrypto getCryptoImplementation() {
        return new CredStashJavaxCrypto();
    }
}
