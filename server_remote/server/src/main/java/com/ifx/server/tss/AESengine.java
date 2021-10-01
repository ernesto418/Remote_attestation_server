package com.ifx.server.tss;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.util.encoders.Hex;

public class AESengine {
    
    public String key;
    public String cyphertext;
    public String initVector = "encryptionIntVec"; //not necessity to be changed, not more that one use per key
    public AESengine(){
    }


    public boolean load_key(String value){
        this.key = value;
        return true;
    }
    /**
     * Given a message to be encrypted as input, generate a random key and use it to encrypt the message
     * @param message String message to be encrypted
     * @param AESengine.key String Space where key encoded hex 
     * @param AESengine.message String Space where the encrypted message encoded in base64 will be stored
     * @return boolean
     */
    public  boolean oneusekey_encryption(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(this.initVector.getBytes("UTF-8"));

            byte[] _keyBytes =generateRadom256key();
            this.key = byteArrayToHexString(_keyBytes);
            SecretKeySpec skeySpec = new SecretKeySpec(_keyBytes, "AES"); 

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        
            byte[] encrypted = cipher.doFinal(value.getBytes());
            this.cyphertext = Base64.getEncoder().encodeToString(encrypted)+"\r";
            return true;
        } catch (Exception ex) {
            return false;
        }
    }


    /***************************************************************
     * Private methods
     **************************************************************/


    /**
     * Generate a radom key of 256 bytes
     * @return bytes byte[]
     */
    private static byte[] generateRadom256key(){
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Convert byte array to hex string
     * {0x00, 0x01, 0x02} -> "000102"
     * @param ba byte array
     * @return hex string
     */
    private static String byteArrayToHexString(byte[] ba) {
        return Hex.toHexString(ba);
    }

}
