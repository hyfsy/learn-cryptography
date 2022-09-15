package com.hyf.crypto;

import java.security.*;
import java.util.Base64;

/**
 * 数字签名
 *
 * @author baB_hyf
 * @date 2022/09/15
 */
public class DigitalSignature {

    public static void main(String[] args) throws Exception {
        String algorithm = "RSA";
        String signatureAlgorithm = "SHA256WithRSA"; // MD5WithRSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 获取签名对象
        Signature signature = Signature.getInstance(signatureAlgorithm);
        // 初始化签名
        signature.initSign(privateKey); // 私钥
        // 传入原文
        signature.update("xxx".getBytes());
        // 签名
        byte[] sign = signature.sign();
        System.out.println(Base64.getEncoder().encodeToString(sign));

        // 验签
        signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(publicKey); // 公钥
        signature.update("xxx".getBytes());
        boolean verify = signature.verify(sign);
        System.out.println(verify);
    }
}
