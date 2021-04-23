
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

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAkey {
	public KeyPair pair;
	
	public RSAkey() {
    }
	
	
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

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    public static boolean import_serverkeys(KeyPair pair) {
    	try {
    		
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    	
    /* To tranform a key to string.
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
    

    
    public boolean import_pair(String Private, String Public) {
    	try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            
    		/* private key*/
            Private = Private.replace("-----BEGIN PRIVATE KEY-----", "");
            Private = Private.replace("-----END PRIVATE KEY-----", "");
            Private = Private.replace("\n", "");
            System.out.println("private " +Private + 9);
    		byte[] Private_byte = Base64.getDecoder().decode(Private);
            PKCS8EncodedKeySpec keySpecPr = new PKCS8EncodedKeySpec(Private_byte);
            RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPr);
            PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(Private_byte));
            
    		/* public key */
            Public = Public.replace("-----BEGIN PUBLIC KEY-----", "");
            Public = Public.replace("-----END PUBLIC KEY-----", "");
            Public = Public.replace("\n", "");
    		byte[] Public_byte = Base64.getDecoder().decode(Public);    		
    	    PKCS8EncodedKeySpec keySpecPu = new PKCS8EncodedKeySpec(Public_byte);
    	    RSAPrivateKey publKey = (RSAPrivateKey) kf.generatePrivate(keySpecPu);    
    	    PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Public_byte));
    	    
    	    this.pair = new KeyPair(pub, key);
    	    
            return true;
        } catch (Exception e) {
        	return false;
        }
    }
    
    }



