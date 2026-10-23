package test.fixtures.java;

import java.security.MessageDigest;
import javax.crypto.Cipher;

public class QuantumSafe {
    public void testAES256() throws Exception {
        // AES-GCM 256-bit
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }

    public void testDigest() throws Exception {
        // CNSA 2.0 compliant SHA-384
        MessageDigest md = MessageDigest.getInstance("SHA-384");
    }
}
