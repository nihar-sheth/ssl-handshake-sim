package coe817project;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Client {

    /**
     * Sends a packet through a DataOuputStream
     *
     * @param input string message to send
     * @param dout DataOutputStream to send message through
     * @throws IOException
     */
    private static void sendPacket(String input, DataOutputStream dout) throws IOException {
        int len = input.length();
        byte[] payload = input.getBytes();
        dout.writeInt(len);
        dout.write(payload, 0, len);
//        System.out.println("packet sent");
    }//method sendPacket

    /**
     * Reads a packet from a DataInputStream
     *
     * @param din the DataInputStream to read a message from
     * @return the string message sent
     * @throws IOException
     */
    private static String getPacket(DataInputStream din) throws IOException {
        int len = din.readInt();
        byte[] payload = new byte[len];
        din.read(payload, 0, len);
//        System.out.println("packet received");
        return new String(payload);
    }//method getPacket

    public static void main(String[] args) {
        System.out.println("Client Starting ...");
        System.out.println("Client Started!");
        Socket socket;
        try {
            int port = 1337;
            System.out.println("Port:" + port);
            String sName = "localhost";
            socket = new Socket(sName, port);
            DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
            DataInputStream din = new DataInputStream(socket.getInputStream());
            int len;

            //sending client hello
            String div = "@";
            //creating payload
            SecureRandom rand = new SecureRandom();
            int nonce1 = rand.nextInt(), nonce_server;
            String protocolVer = "3.0";
            String sessionId = "1337";
            String cipherAlgo = "DES";
            String compressionAlgo = "SHA1";
            String keyEx = "RSA";
            String payload = protocolVer + div + nonce1 + div + sessionId + div
                    + cipherAlgo + div + compressionAlgo;
            
            System.out.println("protocolVer:" + protocolVer +"\n"
                    + "Cipher Algorithm:" + cipherAlgo + "\n"
                    + "Compression:" + compressionAlgo+"\n"
                    + "Key Exchange:" + keyEx);

            //sending payload
            sendPacket(payload, dout);

            //receiving server hello
            payload = getPacket(din);
            System.out.println("Received Server Hello:\n" + payload);
            //read server hello
            String temp[] = payload.split("@");

            if (temp.length == 5) {
                //save server nonce
                nonce_server = Integer.parseInt(temp[1]);
                //get sessionId from server
                sessionId = temp[2];
                //if sent multiple acceptable algorithms, use one server supports
                cipherAlgo = temp[3];
                compressionAlgo = temp[4];
            }//if temp.length

            //receiving server certificate
            //TODO read files from server, save it to pfile, sfile, dfile
            VerSig.setVerSigValues("pubkey", "signature", "data", keyEx, compressionAlgo);
            boolean isVerified = VerSig.verifySignature();
            System.out.println("Server Signature Verified: " + isVerified);
            if (!isVerified) {
                throw new SSLException("Error verifying server certificate");
            }

            //receiving server_hello_done
            System.out.println("receiving server_hello_done");
            payload = getPacket(din);
            if (!payload.equals("1")) {
                throw new SSLException("Error receiving server 'server_hello_done'");
            }

            //sending change_cipher_spec
            System.out.println("sending change_cipher_spec");
            sendPacket("1", dout);

            //receiving server 'change_cipher_spec'
            System.out.println("receiving server change cipher spec");
            payload = getPacket(din);
            if (!payload.equals("1")) {
                throw new SSLException("Error receiving client 'change_cipher_spec'");
            }

            //generate RSA key pair
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyEx);
            keyPairGen.initialize(2048);
            KeyPair pair = keyPairGen.generateKeyPair();
            PrivateKey priKey = pair.getPrivate();
            PublicKey pubKey = pair.getPublic();

            //get server public key
            len = din.readInt();
            byte[] serKey = new byte[len];
            din.read(serKey, 0, len);
//            System.out.println("got server public ");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(serKey);
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PublicKey serverPubKey = keyFact.generatePublic(pubKeySpec);

            //send client public key
            byte[] pubKeyBytes = pubKey.getEncoded();
            dout.writeInt(pubKeyBytes.length);
            dout.write(pubKeyBytes, 0, pubKeyBytes.length);
//            System.out.println("sent client public");

            //get server 'finished'
            System.out.println("receiving server 'finished'");
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            len = din.readInt();
            byte[] msg4 = new byte[len];
            din.read(msg4, 0, len);
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            byte[] partMsg4 = cipher.doFinal(msg4);
            cipher.init(Cipher.UNWRAP_MODE, serverPubKey);
            SecretKey skey = (SecretKey) cipher.unwrap(partMsg4, "DES", Cipher.SECRET_KEY);

            //sending finished
            //TODO generate finished key according to lecture
            cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            System.out.println("sending client 'finished'");
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            payload = "client finished";
            msg4 = cipher.doFinal(payload.getBytes());
            dout.writeInt(msg4.length);
            dout.write(msg4, 0, msg4.length);

            System.out.println("SSL handshake done");
            System.out.println("Starting RLP\n\n");
            boolean isRunning = true;
            Scanner sc = new Scanner(System.in);
            String input;
            String[] fragments;
            MyMac.initMAC("DES","HmacSHA1");
            while(isRunning){
                System.out.println("\nEnter message>");
                input = sc.nextLine();
                if(input.toLowerCase().equals("exit")){
                    isRunning = false;
                    sendPacket("exit",dout);
                    continue;
                }
                fragments = RecordLayer.fragment(10, input);
                MyMac.genMAC(fragments);
                for(String b: fragments){
                    
                    if(!(b == null)){
                    sendPacket(b,dout);
                    temp = b.split("@@");
                    System.out.println("message: " + temp[0]);
                    System.out.println("MAC: " + temp[1]);
                    }//if
                }//for each
            }//while
            
            
            socket.close();
        } catch (IOException e) {
            System.err.println("Error: connection failed");
            e.printStackTrace();
            System.exit(-2);
        } catch (SSLException e) {
            System.err.println("Error: Cannot complete SSL protocol");
            e.printStackTrace();
            System.exit(-3);
        } catch (Exception e) {
            System.out.println("Error");
            e.printStackTrace();
            System.exit(-1);
        }//try catch

    }//main
}//class Client
