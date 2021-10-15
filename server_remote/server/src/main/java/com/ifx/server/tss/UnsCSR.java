package com.ifx.server.tss;

import java.io.IOException;
import java.util.Base64;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Hex;

public class UnsCSR {
    public UnsCSR(){};
    
    public static String getunscsr(PublicKey pub) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // KeyFactory kf = KeyFactory.getInstance("ECDSA");
        // pub_pem = pub_pem.replace("-----BEGIN PUBLIC KEY-----", "");
        // pub_pem = pub_pem.replace("-----END PUBLIC KEY-----", "");
        // pub_pem = pub_pem.replace("\n", "");
        // pub_pem = pub_pem.replace("\r", "");
        // byte[] Public_byte = Base64.getDecoder().decode(pub_pem);    		   
        // PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Public_byte));

        X500Name x500 = new X500Name("CN=test");
        CertificationRequestInfo  info = new CertificationRequestInfo(
                            x500,  SubjectPublicKeyInfo.getInstance(pub.getEncoded()),new DERSet());
        byte[] dataToSign = info.getEncoded(ASN1Encoding.DER);
            return byteArrayToHexString(dataToSign);
    }

    public static String getcsr(PublicKey pub, String signedData_s) {
        try {
        // KeyFactory kf = KeyFactory.getInstance("ECDSA");
        // pub_pem = pub_pem.replace("-----BEGIN PUBLIC KEY-----", "");
        // pub_pem = pub_pem.replace("-----END PUBLIC KEY-----", "");
        // pub_pem = pub_pem.replace("\n", "");
        // pub_pem = pub_pem.replace("\r", "");
        // byte[] Public_byte = Base64.getDecoder().decode(pub_pem);    		   
        // PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Public_byte));


        X500Name x500 = new X500Name("CN=test");
        CertificationRequestInfo  info = new CertificationRequestInfo(
			    		x500,  SubjectPublicKeyInfo.getInstance(pub.getEncoded()),new DERSet());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("ECDSA");


        byte[] signedData = hexStringToByteArray(signedData_s);
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(
                new CertificationRequest(
                    info,
                    sigAlgId, 
                    new DERBitString(signedData)
                )
            );

            byte[] signedCSR = csr.getEncoded();

        //Verify signature validity
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(pub);
        if(csr.isSignatureValid(verifier) != true){
            return null;
        }
        return byteArrayToHexString(signedCSR);
        } catch (Exception e) {
        return null;
        }
    }

    public static PublicKey fromByte2PublicKey(byte[] w) {
        try {
            KeyFactory kf;
            kf = KeyFactory.getInstance("EC");
            byte[] P256_HEAD = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");
            byte[] encodedKey = new byte[P256_HEAD.length + w.length];
            System.arraycopy(P256_HEAD, 0, encodedKey, 0, P256_HEAD.length);
            System.arraycopy(w, 0, encodedKey, P256_HEAD.length, w.length);
            PublicKey pub =kf.generatePublic(new X509EncodedKeySpec(encodedKey));
            return pub;
            } catch (Exception e) {
                return null;
            }
       };



    /***************************************************************
     * Private methods
     **************************************************************/

    /**
     * Convert hex string to byte array
     * "000102" -> {0x00, 0x01, 0x02}
     * @param s hex string
     * @return byte array
     */
    private static byte[] hexStringToByteArray(String s) {
        return Hex.decode(s);
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