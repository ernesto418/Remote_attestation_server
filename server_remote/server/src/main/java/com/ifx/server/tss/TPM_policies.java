package com.ifx.server.tss;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import java.nio.ByteBuffer;


public class TPM_policies {
    

    byte[] Last_policy;
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
    
    private  byte[] Policyreset_creation(int resetcount) throws Exception {
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



}
