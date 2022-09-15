package com.hyf.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 非对称加密
 *
 * @author baB_hyf
 * @date 2022/09/15
 */
public class AsymmetricEncryption {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        String algorithm = "RSA";
        // 生成秘钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 可存储
        byte[] encoded = privateKey.getEncoded();
        String s = Base64.getEncoder().encodeToString(encoded);
        String s2 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println(s);
        System.out.println(s2);

        // 文本还原Key对象
        byte[] decode = Base64.getDecoder().decode(s);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        // 私钥规格
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decode));
        // 公钥规格
        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(s2)));


        // 私钥加密
        Cipher instance = Cipher.getInstance(algorithm);
        instance.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] bytes = instance.doFinal("test".getBytes());
        System.out.println(Base64.getEncoder().encodeToString(bytes));

        // 公钥解密
        instance = Cipher.getInstance(algorithm);
        instance.init(Cipher.DECRYPT_MODE, publicKey);
        bytes = instance.doFinal(bytes);
        System.out.println(new String(bytes));

    }
}
