package me.asu.security;


import me.asu.util.Lang;
import me.asu.util.Hex;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES Coder<br/>
 * secret key length: 128bit, default:  128 bit<br/>
 * mode:  ECB/CBC/PCBC/CTR/CTS/CFB/CFB8 to CFB128/OFB/OBF8 to OFB128<br/>
 * padding: Nopadding/PKCS5Padding/ISO10126Padding/
 *
 * @author Aub
 */
public class AESUtils {

  /**
   * 密钥算法
   */
  private static final String KEY_ALGORITHM = "AES";

  private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

  /**
   * 初始化密钥
   *
   * @return byte[] 密钥
   * @throws Exception
   */
  public static byte[] getSecretKey() {
    SecretKey secretKey = generateSecretKey();
    return secretKey.getEncoded();
  }

  public static SecretKey generateSecretKey() {
    //返回生成指定算法的秘密密钥的 KeyGenerator 对象
    KeyGenerator kg = null;
    try {
      kg = KeyGenerator.getInstance(KEY_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
    //初始化此密钥生成器，使其具有确定的密钥大小
    //AES 要求密钥长度为 128
    kg.init(128);
    //生成一个密钥
    SecretKey secretKey = kg.generateKey();
    return secretKey;
  }

  public static byte[] defaultSecretKey() {
    // 16 bytes
    return "this!is@a#secret".getBytes();
  }

  /**
   * 转换密钥
   *
   * @param key 二进制密钥
   * @return 密钥
   */
  private static Key toKey(byte[] key) {
    //生成密钥
    return new SecretKeySpec(key, KEY_ALGORITHM);
  }


  public static Key toKey(String password) throws Exception {
    String md5 = Lang.md5(password);
    return new SecretKeySpec(md5.substring(0, 16).getBytes(), KEY_ALGORITHM);
  }


  public static byte[] encrypt(InputStream data, String key) throws Exception {
    if (data == null || data.available() == 0) {
      return new byte[0];
    }
    Key k = toKey(key);
    //实例化
    Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
    //使用密钥初始化，设置为加密模式
    cipher.init(Cipher.ENCRYPT_MODE, k);
    byte[] buffer = new byte[8192];
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int n = 0;
    while ((n = data.read(buffer)) != -1) {
      byte[] b = cipher.update(buffer, 0, n);
      if (b != null && b.length > 0) {
        baos.write(b);
      }
    }
    //执行操作
    byte[] b = cipher.doFinal();
    if (b != null && b.length > 0) {
      baos.write(b);
    }

    return baos.toByteArray();

  }

  public static byte[] decrypt(InputStream data, String key) throws Exception {
    if (data == null || data.available() == 0) {
      return new byte[0];
    }
    Key k = toKey(key);
    //实例化
    Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
    //使用密钥初始化，设置为加密模式
    cipher.init(Cipher.DECRYPT_MODE, k);
    byte[] buffer = new byte[8192];
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    int n = 0;
    while ((n = data.read(buffer)) != -1) {
      byte[] b = cipher.update(buffer, 0, n);
      if (b != null && b.length > 0) {
        baos.write(b);
      }
    }
    //执行操作
    byte[] b = cipher.doFinal();
    if (b != null && b.length > 0) {
      baos.write(b);
    }

    return baos.toByteArray();
  }

  /**
   * 加密
   *
   * @param data 待加密数据
   * @param key  密钥
   * @return byte[] 加密数据
   * @throws Exception
   */
  public static byte[] encrypt(byte[] data, Key key) throws Exception {
    return encrypt(data, key, DEFAULT_CIPHER_ALGORITHM);
  }

  /**
   * 加密
   *
   * @param data 待加密数据
   * @param key  密钥
   * @return byte[] 加密数据
   * @throws Exception
   */
  public static byte[] encrypt(byte[] data, String key) throws Exception {
    return encrypt(data, toKey(key), DEFAULT_CIPHER_ALGORITHM);
  }

  /**
   * 加密
   *
   * @param data 待加密数据
   * @param key  二进制密钥
   * @return byte[] 加密数据
   * @throws Exception
   */
  public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
    return encrypt(data, key, DEFAULT_CIPHER_ALGORITHM);
  }


  /**
   * 加密
   *
   * @param data            待加密数据
   * @param key             二进制密钥
   * @param cipherAlgorithm 加密算法/工作模式/填充方式
   * @return byte[] 加密数据
   * @throws Exception
   */
  public static byte[] encrypt(byte[] data, byte[] key, String cipherAlgorithm) throws Exception {
    //还原密钥
    Key k = toKey(key);
    return encrypt(data, k, cipherAlgorithm);
  }

  /**
   * 加密
   *
   * @param data            待加密数据
   * @param key             密钥
   * @param cipherAlgorithm 加密算法/工作模式/填充方式
   * @return byte[] 加密数据
   * @throws Exception
   */
  public static byte[] encrypt(byte[] data, Key key, String cipherAlgorithm) throws Exception {
    //实例化
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    //使用密钥初始化，设置为加密模式
    cipher.init(Cipher.ENCRYPT_MODE, key);
    //执行操作
    return cipher.doFinal(data);
  }


  /**
   * 解密
   *
   * @param data 待解密数据
   * @param key  二进制密钥
   * @return byte[] 解密数据
   * @throws Exception
   */
  public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
    return decrypt(data, key, DEFAULT_CIPHER_ALGORITHM);
  }

  /**
   * 解密
   *
   * @param data     待解密数据
   * @param password 密钥
   * @return byte[] 解密数据
   * @throws Exception
   */
  public static byte[] decrypt(byte[] data, String password) throws Exception {
    return decrypt(data, toKey(password), DEFAULT_CIPHER_ALGORITHM);
  }

  /**
   * 解密
   *
   * @param data 待解密数据
   * @param key  密钥
   * @return byte[] 解密数据
   * @throws Exception
   */
  public static byte[] decrypt(byte[] data, Key key) throws Exception {
    return decrypt(data, key, DEFAULT_CIPHER_ALGORITHM);
  }

  /**
   * 解密
   *
   * @param data            待解密数据
   * @param key             二进制密钥
   * @param cipherAlgorithm 加密算法/工作模式/填充方式
   * @return byte[] 解密数据
   * @throws Exception
   */
  public static byte[] decrypt(byte[] data, byte[] key, String cipherAlgorithm) throws Exception {
    //还原密钥
    Key k = toKey(key);
    return decrypt(data, k, cipherAlgorithm);
  }

  /**
   * 解密
   *
   * @param data            待解密数据
   * @param key             密钥
   * @param cipherAlgorithm 加密算法/工作模式/填充方式
   * @return byte[] 解密数据
   * @throws Exception
   */
  public static byte[] decrypt(byte[] data, Key key, String cipherAlgorithm) throws Exception {
    //实例化
    Cipher cipher = Cipher.getInstance(cipherAlgorithm);
    //使用密钥初始化，设置为解密模式
    cipher.init(Cipher.DECRYPT_MODE, key);
    //执行操作
    return cipher.doFinal(data);
  }

  private static String showByteArray(byte[] data) {
    if (null == data) {
      return null;
    }
    StringBuilder sb = new StringBuilder("{");
    for (byte b : data) {
      sb.append(b).append(",");
    }
    sb.deleteCharAt(sb.length() - 1);
    sb.append("}");
    return sb.toString();
  }

  public static void main(String[] args) throws Exception {
    byte[] key = defaultSecretKey(); //initSecretKey();
    //System.err.println(initSecretKey().length);
    System.out.println("key：" + showByteArray(key));

    Key k = toKey(key);

    String data = "AES数据";
    System.out.println("加密前数据: string:" + data);
    System.out.println("加密前数据: byte[]:" + showByteArray(data.getBytes()));
    System.out.println();
    byte[] encryptData = encrypt(data.getBytes(), k);
    System.out.println("加密后数据: byte[]:" + showByteArray(encryptData));
    System.out.println("加密后数据: hexStr:" + Hex.encodeHexString(encryptData));
    System.out.println();
    byte[] decryptData = decrypt(encryptData, k);
    System.out.println("解密后数据: byte[]:" + showByteArray(decryptData));
    System.out.println("解密后数据: string:" + new String(decryptData));
  }
}