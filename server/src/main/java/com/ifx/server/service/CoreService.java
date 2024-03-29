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
* SOFTWARE
*/

package com.ifx.server.service;

import com.ifx.server.entity.User;
import com.ifx.server.model.*;
import com.ifx.server.repository.UserRepository;
import com.ifx.server.service.security.StatefulAuthService;
import com.ifx.server.service.security.UserRepositoryService;
import com.ifx.server.service.security.UserValidator;
import com.ifx.server.tss.CertificationAuthority;
import com.ifx.server.tss.TPMEngine;
import com.ifx.server.tss.RSAkey;
import com.ifx.server.tss.TPM_policies;
import com.ifx.server.tss.AESengine;
import com.ifx.server.tss.UnsCSR;
import org.bouncycastle.util.encoders.Hex;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;
import tss.tpm.TPMS_QUOTE_INFO;
import tss.tpm.TPM_ALG_ID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.IntStream;

import static com.ifx.server.tss.TPMEngine.*;

@Service
public class CoreService {

    @Autowired
    private CertificationAuthority caManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserValidator userValidator;
    @Autowired
    private UserRepositoryService userService;
    @Autowired
    private StatefulAuthService authService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private SimpMessagingTemplate simpMessagingTemplate;

    public CoreService() {
    }

    static public String printCertificate(X509Certificate c) {
        String out = "";
        try {
            out += "Version: V" + Integer.toString(c.getVersion()) + ", ";
            out += "Format: " + c.getType() + "\n";
            out += "Subject: " + c.getSubjectDN().toString() + "\n";
            out += "Issuer: "+ c.getIssuerDN().toString() + "\n";
            out += "Validity: [From: " + c.getNotBefore().toString() +
                    ", To: " + c.getNotAfter().toString() + "]\n";
            out += "Signature Algorithm: "+ c.getSigAlgName() + "\n";
            out += "Public Key: "+ c.getPublicKey().toString() + "\n";
            out += "Signature: "+ Hex.toHexString(c.getSignature()) + "\n";
        } catch (Exception e) {
        }
        return out;
    }

    private String viewAddModelAttributeUsername(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof AnonymousAuthenticationToken == false) {
            model.addAttribute("username", " " + authentication.getName() + " | Log me out");
            return authentication.getName();
        }
        return null;
    }

    public String viewHome(Model model) {
        viewAddModelAttributeUsername(model);
        return "home";
    }

    public String viewEntry(Model model) {
        viewAddModelAttributeUsername(model);
        model.addAttribute("userForm", new User());
        model.addAttribute("userCount", userRepository.count());
        return "entry";
    }

    public String viewDashboard(Model model) {
        String username = viewAddModelAttributeUsername(model);
        User user = userRepository.findByUsername(username);
        AttuneResp attune = new AttuneResp(user.getEkCrt(), user.getEkCrtAttest(), user.getAkPub(),
                user.getAkName(), user.getMeasureList(), fromStr2IntArray(user.getSha1Bank()),
                fromStr2IntArray(user.getSha256Bank()), fromStr2StrArray(user.getPcrs()), null);
        model.addAttribute("attune", attune);

        AtelicResp atelic = new AtelicResp(user.getQualification(), null);
        model.addAttribute("atelic", atelic);

        CaCerts ca = new CaCerts();
        ca.setRootCAText(caManager.getCA().getRootCAText());
        ca.setRootCAAttest(caManager.getCA().getRootCAAttest());
        model.addAttribute("caCerts", ca);

        return "dashboard";
    }

    public Response<String> restPing() {
        return new Response<String>(Response.STATUS_OK, "Hello Client");
    }

    public Response<String> restGetUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return new Response<String>(Response.STATUS_OK, authentication.getName());
    }

    public Response<String> restUserRegistration(User userForm, BindingResult bindingResult) {
        userValidator.validate(userForm, bindingResult);

        if (bindingResult.hasErrors()) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }

        userService.save(userForm);

        return new Response<String>(Response.STATUS_OK, null);
    }

    public Response<String> restUserSignIn(User userForm) {
        try {
            if (authService.autoLogin(userForm.getUsername(), userForm.getPassword())) {
                return new Response<String>(Response.STATUS_OK, null);
            }
        } catch (BadCredentialsException e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        } catch (UsernameNotFoundException e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
        return new Response<String>(Response.STATUS_ERROR, null);
    }

    public Response<String> restUserSignOut(HttpServletRequest request) {
        try {
            SecurityContextHolder.clearContext();
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            return new Response<String>(Response.STATUS_OK, null);
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, null);
        }
    }

    public Response<Integer> restError(HttpServletResponse response) {
        return new Response<Integer>(Response.STATUS_OK, response.getStatus());
    }

    public Response<AttuneRespDevice> restAttune(@RequestBody Attune attune) {
        try {
            User user = userRepository.findByUsername(attune.getUsername());
            int sorted_pcrs_i = 0;
            int unsorted_pcrs_offset = 0;
            boolean toSort = false;
            String[] unsorted_pcrs = null;
            String[] sorted_pcrs = null;
            int[] sorted_sha1Bank = null;
            int[] sorted_sha2Bank = null;
            String computePcrSha1 = null;
            String computePcrSha256 = null;

            if (user == null || !passwordEncoder.matches(attune.getPassword(),user.getPassword())) {
                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "invalid username or password",null);
            }
            //Nullify the one-use key
            /* Commented for debugging reasons
            user.setPassword(null);
            userRepository.save(user);
            */
            
            //Loading AK just to check the correctness of AK (better geting the problem here and not at the end of the process)
            {
                TPMEngine tpm = new TPMEngine();
            if (tpm.import_publickey(attune.getAkPub()) != true) { //Maybe can be error using a crontructor in a class not initialized
                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "Bad Attestation key, please, regenerate using TPMS_SIG_SCHEME_RSASSA (SHA256)",null);
            }
            }

            //Asserting attributes of Attestation Key
            if (!TPMEngine.assert_AKattributes(attune.getAkPub())) {
                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "Wrong attributes of the \"Attestation Key\"",null);
            }

            user.setAkPub(attune.getAkPub());
            user.setAkName(TPMEngine.computePubKeyName(attune.getAkPub()));
            user.setEkCrt(attune.getEkCrt());
            user.setEkCrtAttest("Failed");

            if (attune.getImaTemplate() != null) {
                List<IMATemplate> IMATemplates = TPMEngine.parseLinuxMeasurements(attune.getImaTemplate(), PLATFORM_PCR);
                String measurementList = TPMEngine.printIMATemplate(IMATemplates);
                computePcrSha1 = Hex.toHexString(TPMEngine.computePcrSha1(IMATemplates));
                computePcrSha256 = Hex.toHexString(TPMEngine.computePcrSha256(IMATemplates));

                user.setMeasureTemplate(attune.getImaTemplate());
                user.setMeasureList(measurementList);
            }

            if (attune.getEkCrt() != null) {
                byte[] crt_der = Hex.decode(attune.getEkCrt());
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream bytes = new ByteArrayInputStream(crt_der);
                X509Certificate eKCert = (X509Certificate)certFactory.generateCertificate(bytes);
                RSAPublicKey key = (RSAPublicKey)eKCert.getPublicKey();
                user.setEkCrt(printCertificate(eKCert));
                user.setEkPub(Hex.toHexString(key.getModulus().toByteArray()));

                caManager.verify(eKCert);
                user.setEkCrtAttest("Passed");
            }

            /**
             * Sorting of SHA1 & SHA256 bank indexes.
             * This is necessary due to tpm hardware behavior.
             * TPM hashing sequence will follow the order of
             * smallest PCR index to biggest PCR index.
             * Since sha1Bank/sha256Bank input is by human so error-prone.
             * Here we check if sha1Bank/sha256Bank input follows such order.
             * Otherwise, lets sort the PCR index and digest array accordingly
             */
            if (attune.getPcrs() != null) {
                unsorted_pcrs = attune.getPcrs();
                sorted_pcrs = new String[unsorted_pcrs.length];
                toSort = true; // a bit foolish to sort even when it is already sorted ¯\_(ツ)_/¯
            } else {
                user.setPcrs(null);
            }

            if (attune.getSha1Bank() != null && attune.getSha1Bank().length != 0) {
                final int[] sha1Bank = attune.getSha1Bank();

                if (toSort) {
                    String[] sha1PCRValue = Arrays.copyOfRange(unsorted_pcrs, 0, sha1Bank.length);
                    unsorted_pcrs_offset = sha1Bank.length;

                    int[] sortedIndices = IntStream.range(0, sha1Bank.length) // first create an index table
                            .boxed().sorted((i, j) -> {
                                if (sha1Bank[i] == sha1Bank[j])
                                    return 0;
                                if (sha1Bank[i] < sha1Bank[j])
                                    return -1;
                                else
                                    return 1;
                            })
                            .mapToInt(ele -> ele).toArray();
                    for (int i = 0; i < sortedIndices.length; i++) {
                        sorted_pcrs[sorted_pcrs_i++] = sha1PCRValue[sortedIndices[i]];
                    }
                }
                sorted_sha1Bank = IntStream.of(sha1Bank).boxed().sorted(Comparator.naturalOrder()).mapToInt(i -> i).toArray();
                user.setSha1Bank(Arrays.toString(sorted_sha1Bank));

                /* Check PCR10 same as template re-compute value */
                if (computePcrSha1 != null) {
                    for (int i = 0; i < sorted_sha1Bank.length; i++) {
                        if (sorted_sha1Bank[i] == TPMEngine.PLATFORM_PCR) {
                            if (!sorted_pcrs[i].equalsIgnoreCase(computePcrSha1)) {
                                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "SHA1 PCR-10 value mismatch with template re-computed value (check if IMA configuration is done correctly)",null);
                            }
                        }
                    }
                }
            } else
                user.setSha1Bank(null);
            if (attune.getSha256Bank() != null && attune.getSha256Bank().length != 0) {
                int[] sha2Bank = attune.getSha256Bank();
                int sha256_start_i = sorted_pcrs_i;

                if (toSort) {
                    String[] sha2PCRValue = Arrays.copyOfRange(unsorted_pcrs, unsorted_pcrs_offset, unsorted_pcrs.length);

                    int[] sortedIndices = IntStream.range(0, sha2Bank.length) // first create an index table
                            .boxed().sorted((i, j) -> {
                                if (sha2Bank[i] == sha2Bank[j])
                                    return 0;
                                if (sha2Bank[i] < sha2Bank[j])
                                    return -1;
                                else
                                    return 1;
                            })
                            .mapToInt(ele -> ele).toArray();
                    for (int i = 0; i < sortedIndices.length; i++) {
                        sorted_pcrs[sorted_pcrs_i++] = sha2PCRValue[sortedIndices[i]];
                    }
                }
                sorted_sha2Bank = IntStream.of(sha2Bank).boxed().sorted(Comparator.naturalOrder()).mapToInt(i -> i).toArray();
                user.setSha256Bank(Arrays.toString(sorted_sha2Bank));

                /* Check PCR10 same as template re-compute value */
                if (computePcrSha256 != null) {
                    for (int i = 0; i < sorted_sha2Bank.length; i++) {
                        if (sorted_sha2Bank[i] == TPMEngine.PLATFORM_PCR) {
                            if (!sorted_pcrs[sha256_start_i + i].equalsIgnoreCase(computePcrSha256)) {
                                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "SHA256 PCR-10 value mismatch with template re-computed value (check if IMA configuration is done correctly)",null);
                            }
                        }
                    }
                }
            } else
                user.setSha256Bank(null);
            if (toSort)
                user.setPcrs(Arrays.toString(sorted_pcrs));
            /**
             * Sorting END
             */

            //key for TPM policy creation and sharing PuK
            RSAkey RSAk = new RSAkey();
            //First generate a public/private key pair
            RSAk.generateKeyPair();            
            String Private_key =  RSAk.PrivateKeytoPEM();
            String Public_pem = RSAk.PublicKeytoPEM();
            //Store the private and Public keys NOT SAFE PROCESS, DO NOT USE IN REAL APPLICATIONS
            user.setPiV_PEM(Private_key);
            user.setPuB_PEM(Public_pem);

            String AESkey_credential;
            AESengine AESengine = new AESengine();

            //Encrypting AuthPub and using decryption key as credential
            
            if (user.getEkPub() != null && user.getAkName() != null &&
                    user.getEkPub() != "" && user.getAkName() != "") {
                        



                        //Encrypting Auth_PuK
                        AESengine.oneusekey_encryption(Public_pem);

                        // Encrypted qualification
                        AESkey_credential = TPMEngine.makeCredential(user.getEkPub(), user.getAkName(), AESengine.key);
            } else {
                // qualification in plain
                //atelicResp.setQualification(qualification);
                return new Response<AttuneRespDevice>(Response.STATUS_ERROR, "Please, ask to the manager of this account to set the EkPub and the AkName of the device to be attested", null); //modification, we dont want to sent a qualification plain text
            }
            AttuneRespDevice resp_dev = new AttuneRespDevice(AESkey_credential,AESengine.cyphertext);

            userRepository.save(user);
            /**
             * Send response to active clients via websocket
             */
            try {
                AttuneResp resp = new AttuneResp(user.getEkCrt(), user.getEkCrtAttest(), user.getAkPub(), user.getAkName(),
                        user.getMeasureList(), sorted_sha1Bank, sorted_sha2Bank, sorted_pcrs, new String[] {computePcrSha1, computePcrSha256});
                simpMessagingTemplate.convertAndSendToUser(user.getUsername(), "/topic/private-test",
                        new Response<AttuneResp>(Response.STATUS_OK, resp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<AttuneRespDevice>(Response.STATUS_OK, null,resp_dev);
        } catch (Exception e) {
            return new Response<AttuneRespDevice>(Response.STATUS_ERROR, e.toString(),null);
        }
    }


    public Response<String> restKCV(@RequestBody KCV KCV) {
        try {
            User user = userRepository.findByUsername(KCV.getUsername());
            //if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
            if (user == null) {//Modification, we dont want the necessity of use the password to validate the RB-pi status
                return new Response<String>(Response.STATUS_ERROR, "invalid username", null);
            }

            /**
             * We will start the validation of all the coming information:
             * 1. SeKcertificate is a certificate TPM_generated and TPM_ST_ATTEST_CERTIFY
             * 2. SeKcertificate is signed by AK
             * 3. SeKcertificate is validating SeK
             * 4. SeK has the correct policy
             * 5. SeK has the correct attributes
             */
            TPMEngine tpm = new TPMEngine();

            /**
             * Import Sealed key
             */
            if (tpm.import_sealedkey(KCV.getSeKPub()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "Sealed key corrupted");
            }

            /**
             * Import Attestation Key (already validated in attune)
             */
            if (tpm.import_publickey(user.getAkPub()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "Bad public key, please, repeat attune process");
            }


            /**
             * Import Attestation Certificate
             * Also check: TPM_generated and TPM_ST_ATTEST_CERTIFY
             */
            if (tpm.import_AttestationCertificate(KCV.getSeKcert()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "Bad certificate, use TPM2_certify");
            }


            /**
             * Verify authenticity of Attestation Certificate
             */
            if (tpm.verify_signature(tpm.AttestationCertificate.toTpm(),KCV.getCertsig()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "Signature not valid, remember using the same AK used in Attune to sign the certificate");
            }

            /**
             * The Certificate is rightful, now we will read it to assert that the key that is comming in KCV (SeK) is
             * the same that in included in the rightful certificate
             */ 
            if (  (TPMEngine.computePubKeyName(KCV.getSeKPub()).equals(TPMEngine.computePubKeyName(tpm.AttestationCertificate))) != true ) {
                return new Response<String>(Response.STATUS_ERROR, "SeK certificate and SeK name do not correspond");
            }

            /**
             * Now we know that SeK is a key that is loaded in the TPM, it is the moment to check the policy and the attributes of SeK
             * 
             * First step is to generate the Authorized policy in software and compare it with the policy of SeK
             */
            //get Authkey modulus
            String modulus_key = RSAkey.getModulus(user.getPuB_PEM());
            if (modulus_key == null) {
                return new Response<String>(Response.STATUS_ERROR, "Bad Authkey, please, repeat Attune process");
            }


            //get Authkey TPM2_object loaded externally && compute name from the TPM object  (TPM2B_PUBLIC) generated 
            String Auth_key_name = tpm.computePubKeyName(tpm.load_external(modulus_key));

            //Compute Policyauthorized
            TPM_policies policies = new TPM_policies();            
            if (policies.Policyauthorized_creation(Auth_key_name) == null) {
                return new Response<String>(Response.STATUS_ERROR, "Error calculating the Policyauthorized policy digest");
            }

            //Compare policies
            if (Arrays.equals(tpm.sealedKey.authPolicy, policies.Last_policy)!= true) {
                return new Response<String>(Response.STATUS_ERROR, "Sealed key's policy is not correct");
            }

            //assert SeK attributes
            if (assert_SeKattributes(tpm.sealedKey)!= true) {
                return new Response<String>(Response.STATUS_ERROR, "Sealed key's attributes are not correct");
            }

            user.setSeKPub(KCV.getSeKPub());
            userRepository.save(user);

            /**
            * It would be all from KCV process, but we will also provide with the unsigned CSR, to avoid the necesity of create it from the IoT device
            */ 

            byte[] xy = TPMEngine.fromTPM2byte(tpm.sealedKey);
            String uncsr = UnsCSR.getunscsr(UnsCSR.fromByte2PublicKey(xy),KCV.getUsername());
            
            /**
            * All the information is correct, therefore, we can ask to our CA to sing a certificate
            */ 
            //String unscsr  = UnsCSR.getunscsr(pub_pem);
            return new Response<String>(Response.STATUS_OK, null, uncsr);
    
        } catch (Exception e) {
        return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
    }


    public Response<String> restCSR(@RequestBody CSR CSR) {
        try {
            User user = userRepository.findByUsername(CSR.getUsername());
            //if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
            if (user == null) {//Modification, we dont want the necessity of use the password to validate the RB-pi status
                return new Response<String>(Response.STATUS_ERROR, "invalid username", null);
            }
            
             /**
             * We will start the CSR creation
             * 1. Recreate Unsigned_CSR and Create CSR form signature and Unsigned_CSR
             * 2. Send CSR to CA
             * 4. SeK has the correct attributes
             */

            /**
            * 1.
            * Recreate Unsigned_CSR and Create CSR form signature and Unsigned_CSR
            */ 

            TPMEngine tpm = new TPMEngine();
            if (tpm.import_sealedkey(user.getSeKPub()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "Sealed key corrupted");
            }

            byte[] xy = TPMEngine.fromTPM2byte(tpm.sealedKey);

            String csr = UnsCSR.getcsr(UnsCSR.fromByte2PublicKey(xy),CSR.getSignature(),CSR.getUsername());

            /**
            * 2.
            * Send CSR to CA (It is out of the scope of our proyect, we sign it by ourselft)
            */ 
            RSAkey Cakeys = new RSAkey();
            Cakeys.generateKeyPair();

            String X509certificate = UnsCSR.sign(Hex.decode(csr), Cakeys.pair.getPrivate(), UnsCSR.fromByte2PublicKey(xy));

            return new Response<String>(Response.STATUS_OK, null, csr);

    	} catch (Exception e) {
        return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
    }

    public Response<AtelicResp> restAtelicSample(@RequestBody Atelic atelic) {
        try {
            User user = userRepository.findByUsername(atelic.getUsername());
            if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
                return new Response<AtelicResp>(Response.STATUS_ERROR, "invalid username or password", null);
            }

            String qualification = "deadbeef";
            user.setQualification(qualification);
            userRepository.save(user);

            AtelicResp atelicResp = new AtelicResp(qualification, null);
            /**
             * Send response to active clients via websocket
             */
            try {
                simpMessagingTemplate.convertAndSendToUser(atelic.getUsername(), "/topic/private-test",
                        new Response<AtelicResp>(Response.STATUS_OK, atelicResp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp);
        } catch (Exception e) {
            return new Response<AtelicResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<AtelicResp> restAtelic(@RequestBody Atelic atelic) {
        try {
            User user = userRepository.findByUsername(atelic.getUsername());
            //if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
            if (user == null) {//Modification, we dont want the necessity of use the password to validate the RB-pi status
                return new Response<AtelicResp>(Response.STATUS_ERROR, "invalid username", null);
            }
            
            String qualification = TPMEngine.getQualification();
            user.setQualification(qualification);
            userRepository.save(user);

            AtelicResp atelicResp = new AtelicResp(qualification, null);
            if (user.getEkPub() != null && user.getAkName() != null &&
                    user.getEkPub() != "" && user.getAkName() != "") {
                // Encrypted qualification
                String credential = TPMEngine.makeCredential(user.getEkPub(), user.getAkName(), qualification);
                atelicResp.setCredential(credential);
            } else {
                // qualification in plain
                //atelicResp.setQualification(qualification);
                return new Response<AtelicResp>(Response.STATUS_ERROR, "Please, ask to the manager of this account to set the EkPub and the AkName of the device to be attested", null); //modification, we dont want to sent a qualification plain text
            }

            /**
             * Send response to active clients via websocket
             */
            try {
                simpMessagingTemplate.convertAndSendToUser(atelic.getUsername(), "/topic/private-test",
                        new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp));
            } catch (Exception e) {
                // ignore
            }

            /**
             * Respond to REST service
             */
            return new Response<AtelicResp>(Response.STATUS_OK, null, atelicResp);
        } catch (Exception e) {
            return new Response<AtelicResp>(Response.STATUS_ERROR, e.toString(), null);
        }
    }

    public Response<String> restAttest(@RequestBody Attest attest) {
        try {
            User user = userRepository.findByUsername(attest.getUsername());
            //if (user == null || !passwordEncoder.matches(atelic.getPassword(),user.getPassword())) {
            if (user == null) {//Modification, we dont want the necessity of use the password to validate the RB-pi status
                return new Response<String>(Response.STATUS_ERROR, "invalid username");
            }
            int[] sha1Bank = fromStr2IntArray(user.getSha1Bank());
            int[] sha256Bank = fromStr2IntArray(user.getSha256Bank());
            String[] pcrs = fromStr2StrArray(user.getPcrs());

            /**
             *  PCR10 is computed using the IMA template.
             *  Here we take the attest.template as ordering reference.
             *  Now arrange the order of attune.template to match with the reference
             *  Compute the SHA1 & SHA256 digest of the re-ordered template
             *  Use the computed digests as good reference and check it against the quote
             */
            List<IMATemplate> toOrder = TPMEngine.parseLinuxMeasurements(user.getMeasureTemplate(), 10);
            List<IMATemplate> orderRef = TPMEngine.parseLinuxMeasurements(attest.getImaTemplate(), 10);
            List<IMATemplate> ordered = orderIMATemplate(toOrder, orderRef);
            String computedPcrSha1 = Hex.toHexString(TPMEngine.computePcrSha1(ordered));
            String computedPcrSha256 = Hex.toHexString(TPMEngine.computePcrSha256(ordered));
            String measureList = TPMEngine.printIMATemplate(orderRef);
            for (int i = 0; i < sha1Bank.length; i++) {
                if (sha1Bank[i] == TPMEngine.PLATFORM_PCR) {
                    pcrs[i] = computedPcrSha1;
                }
            }
            for (int i = 0; i < sha256Bank.length; i++) {
                if (sha256Bank[i] == TPMEngine.PLATFORM_PCR) {
                    pcrs[sha1Bank.length + i] = computedPcrSha256;
                }
            }

            TPMEngine tpm = new TPMEngine();
            if (tpm.import_publickey(user.getAkPub()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad public key");
            }
            if (tpm.import_pcr(sha1Bank, sha256Bank, pcrs) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad pcr values format");
            }
            
            if (tpm.import_qualification(user.getQualification()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad qualification format or qualification deleted");
            }// we can not nullify the qualification here because in our scheme, almost anybody can send a request and arrive here
            if (tpm.import_quote_signature(attest.getQuote(), attest.getSignature()) != true) {
                return new Response<String>(Response.STATUS_ERROR, "bad quote or signature format");
            }

            AttestResp resp = new AttestResp(attest.getQuote(), attest.getSignature(),
                    Instant.now().toEpochMilli(), tpm.quote.quoted.clockInfo.clock,
                    tpm.quote.quoted.firmwareVersion, null, null,
                    sha1Bank, sha256Bank, pcrs, Hex.toHexString(tpm.quote.quoted.extraData),
                    Hex.toHexString(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrDigest),
                    Hex.toHexString(tpm.computeExpectedPcrsDigest()),
                    Hex.toHexString(tpm.quote.quoted.qualifiedSigner), measureList, null);

            for (int i = 0; i < ((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect.length; i++) {
                if (((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].hash == TPM_ALG_ID.SHA1) {
                    int[] pcrSelect = tpm.pcrBitMap(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].pcrSelect);
                    resp.setSha1Bank(pcrSelect);
                } else if (((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].hash == TPM_ALG_ID.SHA256) {
                    int[] pcrSelect = tpm.pcrBitMap(((TPMS_QUOTE_INFO)tpm.quote.quoted.attested).pcrSelect[i].pcrSelect);
                    resp.setSha256Bank(pcrSelect);
                }
            }

            /**a
             * Check signature
             * It is important to know if the fail was becasue the signature or the quote to delete the qualification when the signature is verifyied
             * ATTEST already verifies the signature, but we neet to make the server able to identify if the error is in the attestation or in the signature
             */
            if (tpm.verify_signature(tpm.quote.quoted.toTpm(),  tpm.quote.signature) != true) {
                try {
                    resp.setOutcome("Error in signature");
                    simpMessagingTemplate.convertAndSendToUser(attest.getUsername(), "/topic/private-test",
                            new Response<AttestResp>(Response.STATUS_ERROR, resp));
                } catch (Exception e) {
                    // ignore
                }
                return new Response<String>(Response.STATUS_ERROR, "Error in signature");
            }
            
            //If the signature was OK, it is a genuine attestation, therefore we can delete the qualification to avoid futures replay attacks
            //If the signature is OK, there is just one try to pass the attestation process
            user.setQualification(null);
            userRepository.save(user);

            /**
             * Execute attestation, check quote and signature
             *
             * Send response to active clients via websocket"00""00"
             * &
             * Respond to REST service
             */
            if (tpm.attest() != true) {
                try {
                    resp.setOutcome("Error in signature, platform measurement, or qualification data");
                    simpMessagingTemplate.convertAndSendToUser(attest.getUsername(), "/topic/private-test",
                            new Response<AttestResp>(Response.STATUS_ERROR, resp));
                } catch (Exception e) {
                    // ignore
                }
                return new Response<String>(Response.STATUS_ERROR, "Error in signature, platform measurement, or qualification data");
            } else {
                    RSAkey RSAk = new RSAkey();
                    RSAk.import_pair(user.getPiV_PEM(),user.getPuB_PEM());
                    int resetCount = tpm.getResetcount();
                    if (resetCount == -1){
                        return new Response<String>(Response.STATUS_ERROR, "Invalid resetCount in quote (normally is becasue the quote has a bad format)");
                    }
                    TPM_policies TPM_policies = new TPM_policies();
                    TPM_policies.Policypcr_creation(Hex.decode(computedPcrSha256));
                    TPM_policies.Policyreset_creation(resetCount);
                    String authorization_signature = RSAk.sign_byte(TPM_policies.Last_policy);
                try {
                    resp.setOutcome("Passed");
                    simpMessagingTemplate.convertAndSendToUser(attest.getUsername(), "/topic/private-test",
                            new Response<AttestResp>(Response.STATUS_OK, resp));
                } catch (Exception e) {
                    // ignore
                }
                return new Response<String>(Response.STATUS_OK, "Passed",authorization_signature);
            }
        } catch (Exception e) {
            return new Response<String>(Response.STATUS_ERROR, e.toString());
        }
    }
}
