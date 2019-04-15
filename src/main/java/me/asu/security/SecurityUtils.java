package me.asu.security;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import me.asu.util.Base64;
import me.asu.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 安全工具.
 *
 * send -> use tfb public key to encrypt
 * receive -> ues merchant private key to decrypt
 *
 * <p>2017 Suk All rights reserved.</p>
 *
 * @author Suk
 * @version 1.0.0
 * @since 2017/7/4 14:54
 */
public class SecurityUtils {

    /**
     * 加密算法RSA.
     */
    public static final String KEY_ALGORITHM = "RSA";
    private static      Logger log           = LoggerFactory.getLogger(SecurityUtils.class);

    // 1024 位的密钥 RSA最大加密明文大小 117, RSA最大解密密文大小 128
    // 最大加密明文大小= (m / 8) - 11
    // RSA最大解密密文大小 = m / 8

    public static PublicKey getPublicKeyRSA(String path)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey = loadPemFile(path);
        if (Strings.isBlank(publicKey)) {
            throw new IOException("密钥不存在。");
        }
        return getPublicKeyRSAFromString(publicKey);
    }

    public static PublicKey getPublicKeyRSAFromString(String publicKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (Strings.isBlank(publicKey)) {
            throw new IOException("密钥不存在。");
        }
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(x509KeySpec);
        return publicK;
    }

    public static PrivateKey getPrivateKeyRSA(String path)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = loadPemFile(path);
        if (Strings.isBlank(privateKey)) {
            throw new IOException("密钥不存在。");
        }
        return getPrivateKeyRSAFromString(privateKey);
    }


    public static PrivateKey getPrivateKeyRSAFromString(String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        return privateK;
    }

    public static byte[] encryptByKey(byte[] data, Key key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
                   BadPaddingException, IllegalBlockSizeException {
        /* 对数据加密 */
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptByKey(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    /**
     * <p>
     * 公钥加密.
     * </p>
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @return byte[]
     * @throws Exception 异常
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(x509KeySpec);
        /* 对数据加密 */
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        return cipher.doFinal(data);
    }

    /**
     * <p>
     * 公钥解密.
     * </p>
     *
     * @param data      要解密的数据
     * @param publicKey 公钥(BASE64编码)
     * @return byte[]
     * @throws Exception 异常
     */
    public static byte[] decryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        return cipher.doFinal(data);
    }

    /**
     * <p>
     * 私钥加密.
     * </p>
     *
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @return byte[]
     * @throws Exception 异常
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        return cipher.doFinal(data);
    }

    /**
     * <P>
     * 私钥解密.
     * </p>
     *
     * @param data       要解密的数据
     * @param privateKey 私钥(BASE64编码)
     * @return byte[]
     * @throws Exception 异常
     */
    public static byte[] decryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        return cipher.doFinal(data);
    }

    private static InputStream loadFile(String path) throws FileNotFoundException {
        File file = new File(path);
        InputStream inputStream;
        if (file.isFile()) {
            inputStream = new FileInputStream(file);
        } else {
            /* try classpath */
            inputStream = SecurityUtils.class.getClassLoader().getResourceAsStream(path);
        }
        return inputStream;
    }

    public static String loadPemFile(String path) throws IOException {
        InputStream inputStream = loadFile(path);
        if (inputStream == null) {
            throw new IOException(path + " 不存在。");
        }
        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(inputStream, "utf-8"));
        String line;
        StringBuilder builder = new StringBuilder(15 << 8);
        while ((line = bufferedReader.readLine()) != null) {
            if (line.startsWith("-----BEGIN") || "".equals(line)) {
                continue;
            }
            if (line.startsWith("-----END")) {
                break;
            }
            builder.append(line);
        }
        return builder.toString();
    }

}
