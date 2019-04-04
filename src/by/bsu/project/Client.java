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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.SecretKey;


public class Client {


    public byte[] encodedParameters;
    public List<String> ClientSupportedCiphers;
    private PublicKey Server_PK_KA;
    private SecretKey SharedKey;
    public Certificate ClientCertificate;


    public Client() {
    }

    public void initClientCertificate(String InputDSAlgorithm, String InputKAlgorithm) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidParameterSpecException, InvalidAlgorithmParameterException {

        ClientCertificate = new Certificate();
        ClientCertificate.initializeCertificateAndGenerateKP(InputDSAlgorithm, InputKAlgorithm);
        ClientCertificate.SelfSignCertificate();

    }


    public boolean verifyServerCertificate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, FileNotFoundException, IOException, InvalidKeySpecException {

        //open the server certificate file
        File X509File = new File("ServerX509.txt");
        byte[] ServerX509Bytes;
        try (FileInputStream X509Stream = new FileInputStream(X509File)) {
            ServerX509Bytes = new byte[(int) X509File.length()];
            X509Stream.read(ServerX509Bytes);
        }

        //look for the occurrences of the 0001000 marker to locate the data in the certificate
        int last_PK_KA=0,last_PK_DS=0,last_KAAlg=0,last_DSAlg=0,last_SSig=0;
        int count=1;
        for (int i = 0; i<X509File.length()-7;i++){
            if ((ServerX509Bytes[i] == 0) && (ServerX509Bytes[i+1] == 0) && (ServerX509Bytes[i+2] == 0) && (ServerX509Bytes[i+3] == 1) &&
                    (ServerX509Bytes[i+4] == 0) && (ServerX509Bytes[i+5] == 0) && (ServerX509Bytes[i+6] == 0) && (ServerX509Bytes[i+7] == 0)) {
                if(count==1)
                    last_PK_KA = i;
                if(count==2)
                    last_PK_DS = i;
                if(count==3)
                    last_KAAlg = i;
                if(count==4)
                    last_DSAlg = i;
                if(count==5) {
                    last_SSig = i;
                    break;
                }
                count++;
            }
        }


        //extract the data from the server certificate
        byte[] Recovered_PK_KA = Arrays.copyOfRange(ServerX509Bytes, 0, last_PK_KA);
        byte[] Recovered_PK_DS = Arrays.copyOfRange(ServerX509Bytes, last_PK_KA+8, last_PK_DS);
        byte[] Recovered_KAAlgorithm = Arrays.copyOfRange(ServerX509Bytes, last_PK_DS+8, last_KAAlg);
        byte[] Recovered_DSAlgorithm = Arrays.copyOfRange(ServerX509Bytes, last_KAAlg+8, last_DSAlg);
        byte[] Recovered_SelfSignature = Arrays.copyOfRange(ServerX509Bytes, last_DSAlg+8, last_SSig);

        //Signature algorithm
        String DSAlgorithm;
        if ("SHA1withDSA".equals(new String(Recovered_DSAlgorithm,"UTF-8")))
            DSAlgorithm = "DSA";
        else
            DSAlgorithm = "RSA";

        //decode the public keys
        X509EncodedKeySpec X509_Enc_PK_DS = new X509EncodedKeySpec(Recovered_PK_DS);
        KeyFactory keyFactory = KeyFactory.getInstance(DSAlgorithm);
        PublicKey Srv_PK_DS = keyFactory.generatePublic(X509_Enc_PK_DS);

        X509EncodedKeySpec X509_Enc_PK_KA = new X509EncodedKeySpec(Recovered_PK_KA);
        keyFactory = KeyFactory.getInstance(new String(Recovered_KAAlgorithm,"UTF-8"));
        PublicKey Srv_PK_KA = keyFactory.generatePublic(X509_Enc_PK_KA);

        Server_PK_KA = Srv_PK_KA;

        //Initialize the signature and verify
        Signature DSSign = Signature.getInstance(new String(Recovered_DSAlgorithm,"UTF-8"));

        //Separate server public
        DSSign.initVerify(Srv_PK_DS);

        //pass the data to be signed
        DSSign.update(Srv_PK_KA.getEncoded());
        DSSign.update(Srv_PK_DS.getEncoded());
        DSSign.update(Recovered_KAAlgorithm);
        DSSign.update(Recovered_DSAlgorithm);

        //verify if the signature obtained is the one in the certificate
        boolean res = DSSign.verify(Recovered_SelfSignature);

        return res;
    }


    public void chooseCurrentCipher(List<String> SupportedCiphers, Certificate ServerCertificate, Certificate ClientCertificate){

        //A random cipher is chosen from supported
        Random rnd = new Random();
        String CurrCipher = SupportedCiphers.get(rnd.nextInt(SupportedCiphers.size()));
        System.out.println("\n-Client randomly choose: " + CurrCipher);

        ServerCertificate.CurrentCipher = CurrCipher;
        ClientCertificate.CurrentCipher = CurrCipher;

    }


    public void createHandshake() throws IOException {

        try (FileOutputStream ServerX509 = new FileOutputStream("Handshake.txt")) {
            ServerX509.write(ClientCertificate.PK_KA.getEncoded());
        }
    }

    public void generateSecret() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException {

        //suppose the name of the cipher is in the first three letters of the current
        ClientCertificate.KAgree.doPhase(Server_PK_KA, true);
        SharedKey = ClientCertificate.KAgree.generateSecret(ClientCertificate.CurrentCipher.substring(0, ClientCertificate.CurrentCipher.indexOf('/')));

    }



    public void encrypt(String input,Server Srv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        Cipher CltCipher = Cipher.getInstance(ClientCertificate.CurrentCipher);
        CltCipher.init(Cipher.ENCRYPT_MODE, SharedKey);

        //If we are not in CBC encodedParameters it is NULL
        if (Srv.ServerCertificate.CurrentCipher.contains("CBC"))
            encodedParameters = CltCipher.getParameters().getEncoded();

        //NoPadding requires that the input be a multiple of 8 bytes
        if (Srv.ServerCertificate.CurrentCipher.contains("NoPadding")) {
            while (input.length() % 8 != 0)
                input = input + " ";
        }

        //generate encrypted and write it in the file
        byte[] cipher = CltCipher.doFinal(input.getBytes());

        try (FileOutputStream CipherFile = new FileOutputStream("Cipher.txt")) {
            CipherFile.write(cipher);
            CipherFile.close();
        }

        System.out.println("\n Client sent an encrypted message! (" + cipher +")");

    }

    public void decrypt(Server Srv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException {

        //read the encrypted file
        File CipherFile = new File("Cipher.txt");
        byte[] cipher;
        try (FileInputStream CipherStream = new FileInputStream(CipherFile)) {
            cipher = new byte[(int) CipherFile.length()];
            CipherStream.read(cipher);
            CipherStream.close();
        }

        Cipher CltCipher = Cipher.getInstance(ClientCertificate.CurrentCipher);

        //extract the encryption parameters if present
        if (Srv.ServerCertificate.CurrentCipher.contains("CBC")) {
            AlgorithmParameters DESparams = AlgorithmParameters.getInstance(Srv.ServerCertificate.CurrentCipher.substring(0,Srv.ServerCertificate.CurrentCipher.indexOf("/")));
            DESparams.init(Srv.encodedParameters);
            CltCipher.init(Cipher.DECRYPT_MODE, SharedKey, DESparams);
        }
        else
            CltCipher.init(Cipher.DECRYPT_MODE, SharedKey);

        //Decipher
        byte[] decrypted  = CltCipher.doFinal(cipher);

        System.out.println("\n Client decrypted a message: " + new String(decrypted, "UTF-8"));


    }
}
