
package me.asu.security;


import me.asu.util.io.Streams;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PBEUtils {

  private static final Logger LOGGER = LoggerFactory.getLogger(PBEUtils.class);
  /**
   * JAVA6
   * PBEWITHMD5ANDDES
   * PBEWITHMD5ANDTRIPLEDES
   * PBEWITHSHAANDDESEDE
   * PBEWITHSHA1ANDRC2_40
   * PBKDF2WITHHMACSHA1
   */
  public static final String ALGORITHM = "PBEWITHMD5ANDDES";

  //Security.addProvider(new com.sun.crypto.provider.SunJCE());

  public static final int ITERATION_COUNT = 8;


  public static byte[] initSalt() throws Exception {
    SecureRandom random = new SecureRandom();
    return random.generateSeed(8);
  }

  public static byte[] defaultSalt() {
    return "bruceasu".getBytes();
  }

  public static String defaultPassword() {
    return "bruceasu@gmail.com";
  }

  private static Key toKey(String password) throws Exception {
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
    SecretKey secretKey = keyFactory.generateSecret(keySpec);

    return secretKey;
  }

  public static void encrypt(File fileIn, File fileOut,
                             String password, byte[] salt) throws Exception {
    long start = System.currentTimeMillis();
    LOGGER.info("begin encrypt " + fileIn + " to " + fileOut);
    Key key = toKey(password);
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    InputStream in = Streams.fileIn(fileIn);
    OutputStream os = Streams.fileOut(fileOut);
    copy(in, os, cipher);
    LOGGER.info("finish encrypt " + fileIn + " to " + fileOut);
    long end = System.currentTimeMillis();
    LOGGER.info("cost:  " + (end - start) + " ms.");
  }

  public static byte[] decrypt(File fileIn, String password, byte[] salt) throws Exception {
    long start = System.currentTimeMillis();
    LOGGER.info("begin decrypt " + fileIn);
    Key key = toKey(password);
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

    InputStream in = Streams.fileIn(fileIn);
    ByteArrayOutputStream baos = new ByteArrayOutputStream(4096);
    copy(in, baos, cipher);

    LOGGER.info("finish decrypt " + fileIn);
    long end = System.currentTimeMillis();
    LOGGER.info("cost:  " + (end - start) + " ms.");
    return baos.toByteArray();
  }

  public static PipedInputStream decryptToStream(final InputStream in,
                                                 final String password, final byte[] salt) throws Exception {
    final long start = System.currentTimeMillis();
    LOGGER.info("begin decrypt ");
    Key key = toKey(password);
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
    final Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

    final PipedInputStream pis = new PipedInputStream();
    final PipedOutputStream pos = new PipedOutputStream(pis);
    new Thread() {
      {
        setDaemon(true);
        start();
      }

      @Override
      public void run() {
        copy(in, pos, cipher);
        LOGGER.info("finish decrypt");
        long end = System.currentTimeMillis();
        LOGGER.info("cost:  " + (end - start) + " ms.");
      }
    };

    return pis;
  }

  private static void copy(InputStream in, OutputStream pos, Cipher cipher) {
    byte buffer[] = new byte[1024];
    int len = 0;
    while (true) {
      try {
        len = in.read(buffer);
        if (len == -1) {
          break;
        } else if (len == buffer.length) {
          byte[] bytes = cipher.update(buffer, 0, len);
          Streams.write(pos, bytes);
        } else {
          byte[] bytes = cipher.doFinal(buffer, 0, len);
          Streams.write(pos, bytes);
        }
      } catch (IOException e) {
        e.printStackTrace();
        break;
      } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
        break;
      } catch (BadPaddingException e) {
        e.printStackTrace();
        break;
      }
    }
    Streams.safeClose(in);
    Streams.safeClose(pos);
  }


  public static byte[] encrypt(byte[] data, String password, byte[] salt) throws Exception {
    Key key = toKey(password);
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    return cipher.doFinal(data);
  }

  public static byte[] decrypt(byte[] data, String password, byte[] salt) throws Exception {
    Key key = toKey(password);
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUNT);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
    return cipher.doFinal(data);
  }


}
