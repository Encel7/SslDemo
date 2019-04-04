package by.bsu.project;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Connection {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, Exception{
        System.setProperty("jdk.crypto.KeyAgreement.legacyKDF","true");

        Connection Run = new Connection();
        Run.demoSSL();
    }

    public void demoSSL() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, FileNotFoundException, InvalidKeySpecException, Exception {

        //For those carrying out the project alone the Supported Ciphers are fixed and saved in a file
        Path ServerCiphersFile = Paths.get("ServerSupportedCiphers.txt");
        Path ClientCiphersFile = Paths.get("ClientSupportedCiphers.txt");
        writeClientAndServerSupportedCiphersFiles(ServerCiphersFile,ClientCiphersFile);

        //Choice of the KA algorithm. More than choice, an obligation
        String KAAlgorithm = "DiffieHellman";
        System.out.println("\n-KA algorithm: DiffieHellman");

        //Choice of the signature algorithm
        System.out.println("\n-Choose a DS algorithm");
        System.out.println(" 1. SHA1withDSA    2. SHA1withRSA    3. SHA256withRSA");

        String DSAlgorithm = "";
        while ("".equals(DSAlgorithm)) {
            System.out.print(" Make your choice: ");
            Scanner input = new Scanner(System.in);
            String DSchoiche = input.next();

            switch (DSchoiche) {
                case "1":
                    System.out.println("\n-DS Algorithm: SHA1withDSA");
                    DSAlgorithm = "SHA1withDSA";
                    break;
                case "2":
                    System.out.println("\n-DS Algorithm: SHA1withRSA");
                    DSAlgorithm = "SHA1withRSA";
                    break;
                case "3":
                    System.out.println("\n-DS Algorithm: SHA256withRSA");
                    DSAlgorithm = "SHA256withRSA";
                    break;
                default:
                    System.out.println(" Wrong choice!");
                    break;
            }
        }

        //Initialize Server and its certificate
        Server Srv = new Server();
        Srv.initServerCertificate(DSAlgorithm, KAAlgorithm);
        System.out.println("\n-Server's certificate created.");

        //Initialize Client
        Client Clt = new Client();

        //The client checks the server's signature and saves the server's public for the KA
        if (Clt.verifyServerCertificate())
            System.out.println("\n-Client has successfully verified the X509 Server's certificate!");
        else {
            System.out.println("\n!ERROR: Server signature is NOT valid!");
            return;
        }

        // create client certificate
        Clt.initClientCertificate(DSAlgorithm, KAAlgorithm);
        System.out.println("\n-Client's certificate created.");


        //read the ciphers supported by Server and Client and save them
        Srv.ServerSupportedCiphers = Files.readAllLines(ServerCiphersFile);
        Clt.ClientSupportedCiphers = Files.readAllLines(ClientCiphersFile);


        //read the file encryption supported by the server and I keep only those that are also supported by the client
        List<String> SupportedCiphers = Srv.ServerSupportedCiphers;
        SupportedCiphers.retainAll(Clt.ClientSupportedCiphers);
        if (SupportedCiphers.isEmpty()){
            System.out.println("\n-No Common Supported ciphers!");
            return;
        }
        System.out.println("\n-Common Supported ciphers: " + Arrays.toString(SupportedCiphers.toArray()));


        //client chooses a common cipher and sets the current cipher
        //chosen in the certified Server and Client classes
        Clt.chooseCurrentCipher(SupportedCiphers, Srv.ServerCertificate, Clt.ClientCertificate);


        //client will generate the handshake
        Clt.createHandshake();
        System.out.println("\n-Client's handshake created.");


        //server reads the client's handshake and saves its public KA
        Srv.readClientHandshake();
        System.out.println("\n-Server read Client's handshake.");


        //create the common key to encrypt
        Clt.generateSecret();
        Srv.generateSecret();
        System.out.println("\n-Key Agreement Ended.");


        //Test Communication
        System.out.println("\n---------Starting communication---------");

        Clt.encrypt("H4l0 S3rv3r!",Srv);
        Srv.decrypt(Clt);
        Srv.encrypt("H4l0 Cl13nt!",Clt);
        Clt.decrypt(Srv);
        Clt.encrypt("Wh4ta 'b0ut a b33r?",Srv);
        Srv.decrypt(Clt);
        Srv.encrypt("Sur3 br0!",Clt);
        Clt.decrypt(Srv);

    }

    //supported ciphers are fixed for servers and clients. Initialized here, written to files and then read
    public void writeClientAndServerSupportedCiphersFiles(Path ServerCiphersFile, Path ClientCiphersFile) throws IOException{

        //N.B: The two lists can be different
        List<String> DefaultServerSupportedCiphersList = new ArrayList<> ( Arrays.asList ( "DES/CBC/NoPadding", "DES/CBC/PKCS5Padding", "DES/ECB/NoPadding", "DES/ECB/PKCS5Padding", "DESede/CBC/NoPadding", "DESede/CBC/PKCS5Padding", "DESede/ECB/NoPadding", "DESede/ECB/PKCS5Padding" ) );
        Files.write(ServerCiphersFile,DefaultServerSupportedCiphersList,Charset.defaultCharset());

        List<String> DefaultClientSupportedCiphersList = new ArrayList<> ( Arrays.asList ( "DES/CBC/NoPadding", "DES/CBC/PKCS5Padding", "DES/ECB/NoPadding", "DES/ECB/PKCS5Padding", "DESede/CBC/NoPadding", "DESede/CBC/PKCS5Padding", "DESede/ECB/NoPadding", "DESede/ECB/PKCS5Padding" ) );
        Files.write(ClientCiphersFile,DefaultClientSupportedCiphersList,Charset.defaultCharset());

    }
}
