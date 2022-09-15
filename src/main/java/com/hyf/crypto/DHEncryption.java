package com.hyf.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * DH算法-非对称算法
 *
 * @author baB_hyf
 * @date 2022/09/15
 */
public class DHEncryption {

    public static void main(String[] args) throws Exception {

        System.setProperty("jdk.crypto.KeyAgreement.legacyKDF", "true");

        String algorithm = "DH";
        String secretAlgorithm = "DES";

        // server

        KeyPairGenerator serverKeyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        KeyPair serverKeyPair = serverKeyPairGenerator.genKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        // client

        KeyPairGenerator clientKeyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        DHParameterSpec params = ((DHPublicKey) serverPublicKey).getParams();
        clientKeyPairGenerator.initialize(params);
        KeyPair clientKeyPair = clientKeyPairGenerator.genKeyPair();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
        PublicKey clientPublicKey = clientKeyPair.getPublic();

        // server create secret key

        KeyAgreement serverKeyAgreement = KeyAgreement.getInstance(algorithm);
        serverKeyAgreement.init(serverPrivateKey);
        serverKeyAgreement.doPhase(clientPublicKey, true);
        SecretKey serverSecretKey = serverKeyAgreement.generateSecret(secretAlgorithm);

        // client create secret key

        KeyAgreement clientKeyAgreement = KeyAgreement.getInstance(algorithm);
        clientKeyAgreement.init(clientPrivateKey);
        clientKeyAgreement.doPhase(serverPublicKey, true);
        SecretKey clientSecretKey = clientKeyAgreement.generateSecret(secretAlgorithm);

        Cipher instance = Cipher.getInstance(secretAlgorithm);
        instance.init(Cipher.ENCRYPT_MODE, serverSecretKey);
        byte[] bytes = instance.doFinal("xxx".getBytes());
        System.out.println(Base64.getEncoder().encodeToString(bytes));

        instance = Cipher.getInstance(secretAlgorithm);
        instance.init(Cipher.DECRYPT_MODE, clientSecretKey);
        bytes = instance.doFinal(bytes);
        System.out.println(new String(bytes));

        System.out.println(Base64.getEncoder().encodeToString(serverSecretKey.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(clientSecretKey.getEncoded()));

    }
}
