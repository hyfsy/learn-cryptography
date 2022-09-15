package com.hyf.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 消息摘要算法
 *
 * @author baB_hyf
 * @date 2022/09/15
 */
public class MessageDigestEncryption {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String algorithm = "MD5";
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[] digest = messageDigest.digest("test".getBytes());

        String s = Base64.getEncoder().encodeToString(digest);
        System.out.println(s);

        // 对密文进行迭代
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            String hexString = Integer.toHexString(b & 0xff);
            if (hexString.length() == 1) {
                sb.append(0);
            }
            sb.append(hexString);
        }
        System.out.println(sb);
    }
}
