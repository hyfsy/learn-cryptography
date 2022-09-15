package com.hyf.crypto;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * 对称加密
 *
 * @author baB_hyf
 * @date 2022/09/14
 */
public class SymmetricEncryption {

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String transformation = "DES"; // 加密算法
        // String transformation = "DES/ECB/PKCS5Padding"; // 加密算法/加密模式/填充模式
        String key = "12345678"; // 秘钥，DES秘钥必须为8个字节
        String algorithm = "DES"; // 加密类型

        // 获取加密对象 - 加解密核心对象
        Cipher instance = Cipher.getInstance(transformation);
        // 创建加密规则，秘钥&加密算法
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        // 初始化加密模式和算法
        instance.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // CBC使用
        // IvParameterSpec iv = new IvParameterSpec("123".getBytes()); // iv vector
        // instance.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

        String input = "疼痛";
        // 加密
        byte[] bytes = instance.doFinal(input.getBytes());
        // 输出加密后的数据
        String output = Base64.getEncoder().encodeToString(bytes);
        System.out.println(output);


        bytes = Base64.getDecoder().decode(output);
        instance = Cipher.getInstance(transformation);
        secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        instance.init(Cipher.DECRYPT_MODE, secretKeySpec);
        bytes = instance.doFinal(bytes);
        input = new String(bytes);
        System.out.println(input);
    }

    public static void otherWay() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String algorithm = "DES";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(secretKey.getEncoded());
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        SecretKey secretKey1 = factory.generateSecret(deSedeKeySpec);
        System.out.println(Base64.getEncoder().encodeToString(secretKey1.getEncoded()));
    }

    public static void pbe() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String algorithm = "PBEWithMD5AndDES";
        String password = "12345678";
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        // 1000容量的池子，必须为8个随机字节，混淆池，盐
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(new byte[]{0, 1, 2, 3, 4, 5, 6, 7}, 1000);

        Cipher instance = Cipher.getInstance(algorithm);
        instance.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] bytes = instance.doFinal("xxx".getBytes());
        System.out.println(Base64.getEncoder().encodeToString(bytes));

        instance = Cipher.getInstance(algorithm);
        instance.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        bytes = instance.doFinal(bytes);
        System.out.println(new String(bytes));
    }
}
