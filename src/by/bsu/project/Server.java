package by.bsu.project;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.SecretKey;


public class Server {

    public byte[] encodedParameters = null;
    public List<String> ServerSupportedCiphers;
    private PublicKey Client_PK_KA;
    private SecretKey SharedKey;
    public Certificate ServerCertificate;


    public Server() {
    }

    public void initServerCertificate(String InputDSAlgorithm, String InputKAlgorithm) throws
            IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidParameterSpecException, InvalidAlgorithmParameterException {

        ServerCertificate = new Certificate();
        ServerCertificate.initializeCertificateAndGenerateKP(InputDSAlgorithm, InputKAlgorithm);
        ServerCertificate.SelfSignCertificate();
        createX509certificate();
    }


    private void createX509certificate() throws FileNotFoundException, IOException{

        //Separate the fields with a marker 00010000 to locate
        //the bytes of the various fields read by the client
        FileOutputStream ServerX509 = new FileOutputStream("ServerX509.txt");

        ServerX509.write(ServerCertificate.PK_KA.getEncoded());

        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(1);
        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);

        ServerX509.write(ServerCertificate.PK_DS.getEncoded());

        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(1);
        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);

        ServerX509.write(ServerCertificate.KAAlgorithm.getBytes());

        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(1);
        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);

        ServerX509.write(ServerCertificate.DSAlgorithm.getBytes());

        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(1);
        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);

        ServerX509.write(ServerCertificate.SelfSignature);

        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(1);
        ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);ServerX509.write(0);

    }

    public void readClientHandshake() throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        //Open the handshake file and rebuild the public key
        File HSFile = new File("Handshake.txt");
        byte[] HSBytes;
        try (FileInputStream HSStream = new FileInputStream(HSFile)) {
            HSBytes = new byte[(int) HSFile.length()];
            HSStream.read(HSBytes);
        }

        X509EncodedKeySpec HS_Enc_PK_KA = new X509EncodedKeySpec(HSBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ServerCertificate.KAAlgorithm);
        Client_PK_KA = keyFactory.generatePublic(HS_Enc_PK_KA);

    }


    public void generateSecret() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException {

        //suppose the name of the cipher is in the first three letters of the current
        ServerCertificate.KAgree.doPhase(Client_PK_KA, true);
        SharedKey = ServerCertificate.KAgree.generateSecret(ServerCertificate.CurrentCipher.substring(0, ServerCertificate.CurrentCipher.indexOf('/')));

    }

    public void encrypt(String input, Client Clt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        Cipher SrvCipher = Cipher.getInstance(ServerCertificate.CurrentCipher);
        SrvCipher.init(Cipher.ENCRYPT_MODE, SharedKey);

        //If we are not in CBC encodedParameters it is NULL
        if (Clt.ClientCertificate.CurrentCipher.contains("CBC"))
            encodedParameters = SrvCipher.getParameters().getEncoded();

        //NoPadding requires that the input be a multiple of 8 bytes
        if (Clt.ClientCertificate.CurrentCipher.contains("NoPadding")) {
            while (input.length() % 8 != 0)
                input = input + " ";
        }

        byte[] cipher = SrvCipher.doFinal(input.getBytes());

        try (FileOutputStream CipherFile = new FileOutputStream("Cipher.txt")) {
            CipherFile.write(cipher);
            CipherFile.close();
        }

        System.out.println("\n Server sent an encrypted message! (" + cipher +")");

    }

    public void decrypt(Client Clt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

        //read the encrypted file
        File CipherFile = new File("Cipher.txt");
        byte[] cipher;
        try (FileInputStream CipherStream = new FileInputStream(CipherFile)) {
            cipher = new byte[(int) CipherFile.length()];
            CipherStream.read(cipher);
            CipherStream.close();
        }

        Cipher SrvCipher = Cipher.getInstance(ServerCertificate.CurrentCipher);

        //extract the encryption parameters if present
        if (Clt.ClientCertificate.CurrentCipher.contains("CBC")) {
            AlgorithmParameters DESparams = AlgorithmParameters.getInstance(Clt.ClientCertificate.CurrentCipher.substring(0,Clt.ClientCertificate.CurrentCipher.indexOf("/")));
            DESparams.init(Clt.encodedParameters);
            SrvCipher.init(Cipher.DECRYPT_MODE, SharedKey, DESparams);
        }
        else
            SrvCipher.init(Cipher.DECRYPT_MODE, SharedKey);

        //decipher
        byte[] decrypted  = SrvCipher.doFinal(cipher);

        System.out.println("\n Server decrypted a message: " + new String(decrypted, "UTF-8"));

    }


}
