package coe817project;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Server {
//https://courses.ryerson.ca/d2l/le/content/348141/viewContent/2791488/View

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
        String input = new String();
//        System.out.println("packet received");
        return new String(payload);
    }//method getPacket

    public static void main(String[] args) {
        int port = 1337;
//        String sName = "localhost";
        System.out.println("Server Starting ...");
        System.out.println("Server Started!");
        System.out.println("Port:" + port);
        
        ServerSocket sSocket;
        Socket socket;
        try {
            //Setting up server
            sSocket = new ServerSocket(port);
            socket = sSocket.accept();
            DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
            DataInputStream din = new DataInputStream(socket.getInputStream());
            int len;

            String messages = "";
            String div = "@";
            //receive client hello
            String payload = getPacket(din);
            messages = messages.concat(payload);
            System.out.println("client hello:\n" + payload);

            //sending server hello
            SecureRandom rand = new SecureRandom();

            String protocolVer = "3.0";
            int nonce1 = rand.nextInt(), nonce_client;
            String sessionId = "101";
            String cipherAlgo = "DES";
            String compressionAlgo = "SHA1";
            String keyEx = "RSA";
            
            System.out.println("protocolVer:" + protocolVer +"\n"
                    + "Cipher Algorithm:" + cipherAlgo + "\n"
                            + "Compression:" + compressionAlgo+"\n"
                                    + "Key Exchange:" + keyEx);

            //split client message into parts
            String temp[] = payload.split("@");

            if (temp.length == 5) {
                //TODO? check that protocolVersion is supported
                //save client nonce
                nonce_client = Integer.parseInt(temp[1]);

                //if sessionId != 0, use same session id
                if (!temp[2].equals("0")) {
                    sessionId = temp[2];
                }//if !temp

                //get client cipher algorithms
                String algo = temp[3];
                //check if server supports one of algorithms of client
//                System.out.println("cipher algo: " + algo);
                if (!algo.contains(cipherAlgo)) {
                    throw new SSLException("Client cipher not supported");
                }

                //get client compression algorithms
                algo = temp[4];
//                System.out.println("compression algo: " + algo);
                if (!algo.contains(compressionAlgo)) {
                    throw new SSLException("Client compression algorithm not supported");
                }
            }//if temp.length

            //creating payload
            payload = protocolVer + div + nonce1 + div + sessionId + div
                    + cipherAlgo + div + compressionAlgo;
            System.out.println("Sending Server Hello");

            //sending payload
            sendPacket(payload, dout);
            messages = messages.concat(payload);
            //creating server certificate
            //sending server certificate
            //TODO?? write code for sending the 3 files created: signature, pubkey, data
            GenSig.setGenSigValues("data", keyEx, compressionAlgo);
            GenSig.signFile();

            //sending server_hello_done
            System.out.println("Sending server_hello_done");
            messages = messages.concat("1");
            sendPacket("1", dout);

            //receiving client change_cipher_spec
            System.out.println("receiving client change cipher spec");
            payload = getPacket(din);
            messages = messages.concat(payload);
            if (!payload.equals("1")) {
                throw new SSLException("Error receiving client 'change_cipher_spec'");
            }

            //generate DES key here
            SecretKeyFactory skf = SecretKeyFactory.getInstance(cipherAlgo);
            SecretKey skey = skf.generateSecret(new DESKeySpec(messages.getBytes()));

            //sending change_cipher_spec
            System.out.println("sending change_cipher_spec");
            sendPacket("1", dout);

            //generate RSA key pair
            KeyPairGenerator pkeyGen = KeyPairGenerator.getInstance("RSA");
            pkeyGen.initialize(1024);
            KeyPair pair = pkeyGen.generateKeyPair();
            PrivateKey priKey = pair.getPrivate();
            PublicKey pubKey = pair.getPublic();
            //send server pub key
            byte[] pubKeyBytes = pubKey.getEncoded();
            len = pubKeyBytes.length;
            dout.writeInt(len);
            dout.write(pubKeyBytes, 0, len);
//            System.out.println("sent server public ");
            //get client pub key
            len = din.readInt();
            byte[] cliKey = new byte[len];
            din.read(cliKey, 0, len);
//            System.out.println("got client public");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(cliKey);
            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PublicKey serverPubKey = keyFact.generatePublic(pubKeySpec);

            //encrypt DES key with server pri key and then client pub key
            //E(PUb, E(PRa, Ks) )
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Wrap Ks with client private key
            cipher.init(Cipher.WRAP_MODE, priKey);
            byte[] partMsg4 = cipher.wrap(skey);
            //encrypt result with server public key
            cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
            byte[] msg4 = cipher.doFinal(partMsg4);

            //send des key in 'finished'
            System.out.println("sending server 'finished'");
            dout.writeInt(msg4.length);
            dout.write(msg4, 0, msg4.length);

            //get client 'finished'
            //receiving client 'finished'
            System.out.println("receiving client 'finished'");
            cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            len = din.readInt();
            partMsg4 = new byte[len];
            din.read(partMsg4, 0, len);
            cipher.init(Cipher.DECRYPT_MODE, skey);
            msg4 = cipher.doFinal(partMsg4);
            payload = new String(msg4);
            if (!payload.equals("client finished")) {
                throw new SSLException("Error receiving client 'finished'. Symmetric keys not matching");
            }

            System.out.println("SSL handshake done");
            System.out.println("Starting RLP\n\n");
            boolean isRunning = true;
//            Scanner sc = new Scanner(System.in);
            String input, tempString = "";
            temp = null;
            MyMac.initMAC("DES", "HmacSHA1");
            while (isRunning) {
//                System.out.println("Enter message");
                input = getPacket(din);
                tempString = "";
                if (input.toLowerCase().equals("exit")) {
                    isRunning = false;
                    continue;
                }
                temp = input.split("@@");
                len = Integer.parseInt(temp[0]);
                for (int i = 0; i < len; i++) {
                    input = getPacket(din);
                    temp = input.split("@@");
                    tempString = tempString.concat(temp[0]);
                    System.out.println("fragment: " + temp[0]);
                    System.out.println("MAC: " + temp[1]);
                }//for i
                    System.out.println("Message: " + tempString);
                    System.out.println("");
            }//while

            //ending connection
            socket.close();
            sSocket.close();
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
}//class Server
