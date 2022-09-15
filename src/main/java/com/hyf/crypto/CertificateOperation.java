package com.hyf.crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * @author baB_hyf
 * @date 2022/09/15
 */
public class CertificateOperation {

    public static void main(String[] args) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, InvalidKeyException, NoSuchProviderException, SignatureException {
        // 加载秘钥库
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        // 获取私钥
        Key key = keyStore.getKey("www.baidu.com", "11111".toCharArray());
        // 获取证书
        Certificate certificate = keyStore.getCertificate("www.baidu.com");
        // 获取证书公钥
        PublicKey publicKey = certificate.getPublicKey();
        // 公钥验签
        certificate.verify(publicKey);

        // 秘钥文件加载数字证书
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream("xxx.cer");
        Certificate certificate1 = certificateFactory.generateCertificate(fileInputStream);
    }
}
