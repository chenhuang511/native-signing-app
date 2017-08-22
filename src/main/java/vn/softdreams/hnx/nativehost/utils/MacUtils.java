/**
 *
 * @(#)MacUtils Nov 26, 2014 9:43:33 AM Copyright 2014 Viettel ICT. All rights
 * reserved. VIETTEL PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package vn.softdreams.hnx.nativehost.utils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author minhnn10
 */
public class MacUtils {

    public static String creMsgSig(String data, PrivateKey priKey) throws Exception {

        java.security.Signature s = java.security.Signature.getInstance("SHA1withRSA");
        s.initSign(priKey);
        s.update(data.getBytes("ISO-8859-1"));
        byte[] signature = s.sign();
        // Encrypt data
        return new String(Base64.encode(signature));
    }

    /**
     * Get java.security.privateKey from String
     *
     * @author minhnn10 @date 20/02/2014
     * @param key
     * @return PrivateKey
     * @throws Exception
     */
    public static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        PrivateKey privateKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(key));
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * Get java.security.publicKey from String
     *
     * @author sonhv3 @date 20/02/2014
     * @param key
     * @return PrivateKey
     * @throws Exception
     */
    public static PublicKey getPubKeyFromString(String key) throws Exception {
        PublicKey privateKey = null;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(Base64.decode(key));
        privateKey = keyFactory.generatePublic(pubKeySpec);
        return privateKey;
    }

    /**
     * Verify signature
     *
     * @author minhnn10 @date 20/02/2014
     * @param signature
     * @param pubKey
     * @param data
     * @return boolean
     */
    public static boolean verSig(String signature, PublicKey pubKey, String data) {
        try {
            // decode base64
            byte[] base64Bytes = Base64.decode(signature);
            java.security.Signature sig = java.security.Signature.getInstance("SHA1withRSA");
            sig.initVerify(pubKey);
            sig.update(data.getBytes("ISO-8859-1"));
            return sig.verify(base64Bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
