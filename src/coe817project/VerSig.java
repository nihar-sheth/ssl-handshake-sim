package coe817project;

import java.io.*;
import java.security.*;
import java.security.spec.*;

public final class VerSig {
    private static String pubkeyfile, signaturefile, datafile;
    private static String cipher, compression; 
    
    private VerSig(){
        pubkeyfile = "pubKey";
        signaturefile = "signature";
        datafile = "data";
        cipher = "DSA";
        compression = "SHA1";
    }//constructor VerSig
    
    public static void setVerSigValues(String pfile, String sfile, String dfile,
            String ciph, String comp){
        pubkeyfile = pfile;
        signaturefile = sfile;
        datafile = dfile;
        cipher = ciph;
        compression = comp;
    }
    
    public static boolean verifySignature(){
        boolean isVerified = false;
            try{
                //read public key from file
                FileInputStream keyfs = new FileInputStream(pubkeyfile);
                byte[] encKey = new byte[keyfs.available()];
                keyfs.read(encKey);
                
                //create key factory for public key
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
                KeyFactory kf = KeyFactory.getInstance(cipher);
                //generate public key
                PublicKey pubKey = kf.generatePublic(pubKeySpec);
                
                //read signature from file
                FileInputStream sigfs = new FileInputStream(signaturefile);
                byte[] sigVerify = new byte[sigfs.available()];
                sigfs.read(sigVerify);
                sigfs.close();
                
                //initialize signature verification
                Signature sig = Signature.getInstance(compression+"with"+cipher);
                sig.initVerify(pubKey);
                
                //read file to verify
                FileInputStream datafs = new FileInputStream(datafile);
                BufferedInputStream bin = new BufferedInputStream(datafs);
                
                byte[] buffer = new byte[1024];
                int len;
                while(bin.available() != 0){
                    len = bin.read(buffer);
                    sig.update(buffer,0,len);
                }
                bin.close();
                
                //verify signature
                isVerified = sig.verify(sigVerify);
//                System.out.println("Does the signature match:" + isVerified);
            }catch(Exception e){
                e.printStackTrace();
            }//try catch
            return isVerified;
    }//method verifySignature
}//class VerSig
