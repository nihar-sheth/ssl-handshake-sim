package coe817project;

import java.io.*;
import java.security.*;

public final class GenSig {

    private static String filename, cipher, compression;

    private GenSig(String filename, String cipher, String compression) {
        this.filename = "data";
        this.cipher = "DSA";
        this.compression = "SHA1";
    }//constructor GenSig

    public static void setGenSigValues(String fileToSign, String ciph, String comp) {
        filename = fileToSign;
        cipher = ciph;
        compression = comp;
    }//method setGenSigValues

    public static void signFile() {

        try {
            //create key pair generator for SHA1
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(cipher);
            SecureRandom random = SecureRandom.getInstance(compression + "PRNG");
            keygen.initialize(1024, random);

            //create keypair
            KeyPair pair = keygen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            //create signature using privatekey
            Signature dsa = Signature.getInstance(compression + "with" + cipher);
            dsa.initSign(priv);

            //create signature from filename given
            FileInputStream fs = new FileInputStream(filename);
            BufferedInputStream bin = new BufferedInputStream(fs);
            byte[] buffer = new byte[1024];
            int len;

            while ((len = bin.read(buffer)) >= 0) {
                dsa.update(buffer, 0, len);
            }
            bin.close();

            //create signature from data
            byte[] realSig = dsa.sign();

            //save signature in file "signature"
            FileOutputStream sigfs = new FileOutputStream("signature");
            sigfs.write(realSig);
            sigfs.close();

            //save public key in file "pubKey"
            byte[] key = pub.getEncoded();
            FileOutputStream keyfs = new FileOutputStream("pubKey");
            keyfs.write(key);
            keyfs.close();

        } catch (Exception e) {
            e.printStackTrace();
        }//try catch
    }//method signFile

}//class GenSig
