package com.ifx.server.tss;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import java.nio.ByteBuffer;
import org.bouncycastle.util.encoders.Hex;

public class TPM_policies {
    

    public byte[] Last_policy;
    public TPM_policies(){
        this.Last_policy = ByteBuffer.allocate(32).putInt(0).array();
    }

     /**
     * Create the hash of a policy "TPM2_PolicyCounterTimer" where the reset value of th TPM MUST be
     * the value of resetcount to be satisfied. For more infomation about the policy go to:
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_code_pub.pdf
     * 
     * @param resetcount int TPM resetcount vlue
     * @return byte array Policyreset
     */
    
    public  byte[] Policyreset_creation(int resetcount) throws Exception {
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
    	//byte[] Last_policy = ByteBuffer.allocate(32).putInt(0).array();
    	
    	//Policy_countertimer name
    	byte[] countertimer =  hexStringToByteArray("0000016d");
    	
    	//Last policy + countertimer name + Digest OperandB
    	byte[] Policyreset =new byte[68];
        System.arraycopy(this.Last_policy , 0, Policyreset,                  0, this.Last_policy.length);
        System.arraycopy(countertimer, 0, Policyreset, this.Last_policy.length, countertimer.length); 
        System.arraycopy(fHash       , 0, Policyreset, this.Last_policy.length + countertimer.length, fHash.length);
        this.Last_policy = digest.digest(Policyreset);

    	return this.Last_policy;
    }

     /**
     * Create the hash of a policy "TPM2_PolicyCounterTimer" where the reset value of th TPM MUST be
     * the value of resetcount to be satisfied. For more infomation about the policy go to:
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_code_pub.pdf
     * 
     * @param resetcount int TPM resetcount vlue
     * @return byte array Policyreset
     */
    public  byte[] Policyauthorized_creation(String name) throws Exception {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] key_name = hexStringToByteArray(name);
            
            //Policy_countertimer name (TPM_CC_PolicyAuthorize)
            byte[] Policyauthorize =  hexStringToByteArray("0000016a");
            
            // Oldpolicy | command | keySign
            byte[] Policy_contruction =new byte[this.Last_policy.length + Policyauthorize.length + key_name.length];
            System.arraycopy(this.Last_policy , 0, Policy_contruction,                  0, this.Last_policy.length);
            System.arraycopy(Policyauthorize, 0, Policy_contruction, this.Last_policy.length, Policyauthorize.length); 
            System.arraycopy(key_name       , 0, Policy_contruction, this.Last_policy.length + Policyauthorize.length, key_name.length);
            
            this.Last_policy = digest.digest(Policy_contruction);
            //Two times hashing for this policy
            this.Last_policy = digest.digest(this.Last_policy);
            
            return this.Last_policy;
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * Create the hash of a policy "TPM2_Policypcr". Warning: this function is prepared just to create
     * the policy for PCR 10 and only PCR 10!!. For more infomation about the policy go to:
     * https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_code_pub.pdf
     * 
     * @param PCR Bytes() TPM resetcount vlue
     * @return byte array Policyreset
     */
    
    public  byte[] Policypcr_creation(byte[] PCR10) throws Exception {

    	MessageDigest digest = MessageDigest.getInstance("SHA-256");

    	//PolicyPCSR name configuration
    	byte[] policyPCR_name =  hexStringToByteArray("0000017F");

    	//Selected PCR array (sha256:PCR10 selected) 
        //For more information go to: 
        //https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf
        //section: "10.6.1 TPMS_PCR_SELECT"
    	byte[] PCR10selected =  hexStringToByteArray("00000001000b03000400");
        //digest of PCR selected' Values
        byte[] pcr_digest = digest.digest(PCR10);
    	

    	
    	//Last policy + policyPCR_name + PCR10selected + pcr_digest
    	byte[] Policy_contruction =new byte[this.Last_policy.length + policyPCR_name.length + PCR10selected.length + pcr_digest.length ];
        System.arraycopy(this.Last_policy , 0, Policy_contruction,                  0, this.Last_policy.length);
        System.arraycopy(policyPCR_name, 0, Policy_contruction, this.Last_policy.length, policyPCR_name.length); 
        System.arraycopy(PCR10selected       , 0, Policy_contruction, this.Last_policy.length + policyPCR_name.length, PCR10selected.length);
        System.arraycopy(pcr_digest       , 0, Policy_contruction, this.Last_policy.length + policyPCR_name.length + PCR10selected.length, pcr_digest.length);
        this.Last_policy = digest.digest(Policy_contruction);
    	return this.Last_policy;
    }

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
