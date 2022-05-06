package coe817project;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public final class MyMac {
    private static KeyGenerator keygen;
    private static Key MACKey;
    private static Mac mac;
    private static String keyInst, MacInst;
    private MyMac(){
        keyInst = "DES";
        MacInst = "HmacSHA256";
    }
    public static void initMAC(String keyInstance, String MacInstance) {
        keyInst = keyInstance;
        MacInst = MacInstance;
        try {
            keygen = KeyGenerator.getInstance(keyInst);//"DES"
            SecureRandom srand = new SecureRandom();
            keygen.init(srand);

            MACKey = keygen.generateKey();
            mac = Mac.getInstance(MacInst);//"HmacSHA256"
            mac.init(MACKey);
        } catch (Exception e) {
            System.err.println("Error initializing MAC");
            e.printStackTrace();
        }//try catch
    }//method initMAC

    public static String[] genMAC(String[] message) {
        byte[] MacOutput = null;
        try {
            for(int i = 0; i < message.length; i++){
                String a = message[i];
            byte[] messageBytes = a.getBytes();
            MacOutput = mac.doFinal(messageBytes);
                message[i] = a.concat("@@").concat(new String(MacOutput));
            }//for String
        } catch (Exception e) {
            System.err.println("Error Generating MAC");
            e.printStackTrace();
        }//try catch
        return message;
    }//method genMAC
}
