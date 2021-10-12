
/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* It is a not safe crypto middleware, DO NOT USE in real applications
*/


package com.ifx.server.tss;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.ByteBuffer;
import com.ifx.server.tss.TPM_policies;
import java.math.BigInteger;
import org.bouncycastle.util.encoders.Hex;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAkey {

	public KeyPair pair;
	
	public RSAkey() {
    }
	
	/**
     * Generate a pseudorandom Key peir
     * @return success or fail
     */
    public boolean generateKeyPair() throws Exception {
    	try {
	        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	        generator.initialize(2048, new SecureRandom());
	        this.pair = generator.generateKeyPair();
	        return true;
    	} catch (Exception e) {

    		return false;
        }
    }


    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    /**
     * Verify a signature from the data, signature and public key
     * @param plainText Data signed
     * @param signature
     * @param publicKey Public key used to generate the signature
     * @return success or fail
     */
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public String resetsession_debugg(int resetcount) throws Exception {
       
        TPM_policies TPM_policies = new TPM_policies();

        byte[] policy_session=TPM_policies.Policyreset_creation(resetcount); 
        return Base64.getEncoder().encodeToString(policy_session);
     }


    /**
     * Create an enabler authorization to use the sealed key for the given Reset value
     * @param resetcount Reset value of the TPM
     * @return success or fail
     */
    public String sign_resetsession(int resetcount) throws Exception {
        TPM_policies policies = new TPM_policies();
        byte[] policy_session=policies.Policyreset_creation(resetcount); 
        return sign_byte(policy_session,this.pair.getPrivate());
     }
    	
    /* To tranform a key to PEM.
     * 
     */
    
    public  String PrivateKeytoPEM() {
    	try {
            String encodedString = "-----BEGIN PRIVATE KEY-----\n";
            encodedString = encodedString + Base64.getEncoder().encodeToString(this.pair.getPrivate().getEncoded()) + "\n";
            encodedString = encodedString+"-----END PRIVATE KEY-----\n";
    		return encodedString;
        } catch (Exception e) {
            return "error";
        }
    }
    
    public  String PublicKeytoPEM() {
    	try {
            String encodedString = "-----BEGIN PUBLIC KEY-----\n";
            encodedString =encodedString + Base64.getEncoder().encodeToString(this.pair.getPublic().getEncoded()) +"\n";
            encodedString = encodedString+"-----END PUBLIC KEY-----\n";
    		return encodedString;
        } catch (Exception e) {
            return "error";
        }
    }
    

    /**
     * Import key pairs from PEM format in the class
     * @param Private Private key in PEM
     * @param Public Public key in PEM
     * @return success or fail
     */
    
    public boolean import_pair(String Private, String Public) {
    	try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            
    		/* private key*/
            Private = Private.replace("-----BEGIN PRIVATE KEY-----", "");
            Private = Private.replace("-----END PRIVATE KEY-----", "");
            Private = Private.replace("\n", "");
    		byte[] Private_byte = Base64.getDecoder().decode(Private);
            PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(Private_byte));
            
    		/* public key */
            Public = Public.replace("-----BEGIN PUBLIC KEY-----", "");
            Public = Public.replace("-----END PUBLIC KEY-----", "");
            Public = Public.replace("\n", "");
    		byte[] Public_byte = Base64.getDecoder().decode(Public);    		   
    	    PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Public_byte));
    	    
    	    this.pair = new KeyPair(pub, key);
    	    
            return true;
        } catch (Exception e) {
        	return false;
        }
    }

    /**
     * Get modulus from PEM public key
     * @param Public_PEM Public key in PEM
     * @return String Modulus in hexString
     */
    
    public static String getModulus(String Public) {
    	try {
            /* public key */
            Public = Public.replace("-----BEGIN PUBLIC KEY-----", "");
            Public = Public.replace("-----END PUBLIC KEY-----", "");
            Public = Public.replace("\n", "");
            Public = Public.replace("\r", "");

            
            KeyFactory kf = KeyFactory.getInstance("RSA");
            byte[] keyBytes = Base64.getDecoder().decode(Public.getBytes("UTF-8"));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            PublicKey fileGeneratedPublicKey = kf.generatePublic(spec);
            RSAPublicKey rsaPub  = (RSAPublicKey)(fileGeneratedPublicKey);
            BigInteger publicKeyModulus = rsaPub.getModulus();
            String Modulus=byteArrayToHexString(publicKeyModulus.toByteArray());
            Modulus = Modulus.substring(2);


    	    
            return Modulus;
        } catch (Exception e) {
        	return null;
        }
    }

    /***************************************************************
     * Private methods
     **************************************************************/

    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }
    

    /**
     * //to be eliminated from this section, by ernesto
     * Create the hash of a policy "TPM2_PolicyCounterTimer" where the reset value of th TPM MUST be
     * the value of resetcount to be satisfied. For more infomation about the policy go to:
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_code_pub.pdf
     * 
     * @param resetcount int TPM resetcount vlue
     * @return byte array Policyreset
     */
    
    private  static byte[] Policyreset_creation(int resetcount) throws Exception {
    	//operandB configuration
    	byte[] policy =  hexStringToByteArray("00100000");
    	
    	//operandB
    	byte[] operandoB = ByteBuffer.allocate(4).putInt(resetcount).array();
    	
    	//Hash(operandB + Configuration)
        byte[] fInput = new byte[8];
        System.arraycopy(operandoB,0,fInput,0,4);
        System.arraycopy(policy, 0, fInput, 4, 4);  
    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
    	byte[] fHash = digest.digest(fInput);
    	
    	//input the digest of the last policy (here, no one)
    	byte[] Last_policy = ByteBuffer.allocate(32).putInt(0).array();
    	
    	//Policy_countertimer name
    	byte[] countertimer =  hexStringToByteArray("0000016d");
    	
    	//Last policy + countertimer name + Digest OperandB
    	byte[] Policyreset =new byte[68];
        System.arraycopy(Last_policy , 0, Policyreset,                  0, Last_policy.length);
        System.arraycopy(countertimer, 0, Policyreset, Last_policy.length, countertimer.length); 
        System.arraycopy(fHash       , 0, Policyreset, Last_policy.length + countertimer.length, fHash.length);
        byte[] Hash_policyreset = digest.digest(Policyreset);

    	return Hash_policyreset;
    }

    /**
     * Sing a given byte array using the given privatekey
     * 
     * @param msg byte[] Message to be signed
     * @param privateKey PrivateKey Private key to sign  msg
     * @return String array signature
     */
    private static String sign_byte(byte[] msg,PrivateKey privateKey) throws Exception { //by ernesto, to be changed with bouncy castle fucntion
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(msg);

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
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



