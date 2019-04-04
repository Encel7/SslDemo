package by.bsu.project;

import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;


public class Certificate {

    public KeyAgreement KAgree;
    private KeyPair KAPair;
    public PublicKey PK_KA;
    private KeyPair DSPair;
    public PublicKey PK_DS;
    public String DSAlgorithm;
    public String KAAlgorithm;
    public String CurrentCipher;
    public byte[] SelfSignature;

    public Certificate() {
    }

    public void initializeCertificateAndGenerateKP(String CertDSAlgorithm, String CertKAAlgorithm) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException {

        //Algorythms list
        DSAlgorithm = CertDSAlgorithm;
        KAAlgorithm = CertKAAlgorithm;

        //Diffie-Hellmann Configurations
        DHParameterSpec DHPSpec;
        AlgorithmParameterGenerator APGen = AlgorithmParameterGenerator.getInstance(KAAlgorithm);
        APGen.init(512);
        DHPSpec =  APGen.generateParameters().getParameterSpec(DHParameterSpec.class);

        //Creating parameters for DH
        KeyPairGenerator KPGen = KeyPairGenerator.getInstance(KAAlgorithm);
        KPGen.initialize(DHPSpec);

        //Generating KeyPair for DH
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        KPGen.initialize(1024, random);
        KAPair = KPGen.genKeyPair();
        PK_KA = KAPair.getPublic();

        //Initialize the KeyAgreement with private
        KAgree = KeyAgreement.getInstance(KAAlgorithm);
        KAgree.init(KAPair.getPrivate());


        //take it for granted that the possible signature algorithms can only be
        //SHA1withDSA, SHA1withRSA, SHA256withRSA
        if ("SHA1withDSA".equals(DSAlgorithm))
            KPGen = KeyPairGenerator.getInstance("DSA");
        else
            KPGen = KeyPairGenerator.getInstance("RSA");

        KPGen.initialize(1024, random);
        DSPair = KPGen.genKeyPair();
        PK_DS = DSPair.getPublic();
    }


    public void SelfSignCertificate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // Sign used the requested algorithm
        Signature DSSign = Signature.getInstance(DSAlgorithm);
        PrivateKey PRIVATE_DS = DSPair.getPrivate();
        DSSign.initSign(PRIVATE_DS);

        DSSign.update(PK_KA.getEncoded());
        DSSign.update(PK_DS.getEncoded());
        DSSign.update(KAAlgorithm.getBytes());
        DSSign.update(DSAlgorithm.getBytes());


        SelfSignature = DSSign.sign();

    }

}