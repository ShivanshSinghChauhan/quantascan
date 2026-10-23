package test.fixtures.java;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;

public class LegacyCrypto {
    // Hardcoded Certificate PEM
    public static final String CERT = 
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBkTCB+wIJALa123...\n" +
        "-----END CERTIFICATE-----";

    public void testRSAKeyGen() throws Exception {
        // Pre-quantum RSA key generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }

    public void testECKeyGen() throws Exception {
        // Pre-quantum EC key generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        kpg.generateKeyPair();
    }

    public void testSignatures() throws Exception {
        // RSA signature
        Signature sig = Signature.getInstance("SHA256withRSA");
    }

    public void testLegacyCipher() throws Exception {
        // Broken DES cipher
        Cipher cipher = Cipher.getInstance("DES");
    }

    public void testDigest() throws Exception {
        // SHA-256 (sub-threshold for CNSA 2.0)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
