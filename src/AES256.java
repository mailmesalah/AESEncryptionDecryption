import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256 {
	private static String initializationVector = "sdawwwwwwwwwsdsa";
	private static String salt = "fasda";
	private static int pswdIterations = 10;
	private static int keySize = 256;

	public static void encrypt(String password, String inputFile,
			String outputFile) throws NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			InvalidParameterSpecException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {

		byte[] saltBytes = salt.getBytes("UTF-8");
		byte[] ivBytes = initializationVector.getBytes("UTF-8");

		// Derive the key, given password and salt.
		SecretKeyFactory factory = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes,
				pswdIterations, keySize);

		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivBytes));
		byte[] encrypted = cipher.doFinal(Files.readAllBytes(Paths
				.get(inputFile)));
		Files.write(Paths.get(outputFile), encrypted);

	}

	public static void decrypt(String password, String inputFile,
			String outputFile) throws NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException {

		byte[] saltBytes = salt.getBytes("UTF-8");
		byte[] ivBytes = initializationVector.getBytes("UTF-8");

		// Derive the key, given password and salt.
		SecretKeyFactory factory = SecretKeyFactory
				.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes,
				pswdIterations, keySize);

		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		// Decrypt the message, given derived key and initialization vector.
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));

		byte[] original = cipher.doFinal(Files.readAllBytes(Paths
				.get(inputFile)));
		Files.write(Paths.get(outputFile), original);
	}

	public static void main(String[] args) {
		String password = "password";
		/*
		 * Used to remove the restriction of using 256 bit encryption
		 */
		try {
			Field field = Class.forName("javax.crypto.JceSecurity")
					.getDeclaredField("isRestricted");
			field.setAccessible(true);
			field.set(null, java.lang.Boolean.FALSE);
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}
		/**********************************************************/
		
		System.out.println("AES 256");
		if (args.length == 3) {
			if (args[0].equals("-E")) {
				try {
					encrypt(password, args[1], args[2]);
				} catch (InvalidKeyException | NoSuchAlgorithmException
						| InvalidKeySpecException | NoSuchPaddingException
						| InvalidParameterSpecException
						| IllegalBlockSizeException | BadPaddingException
						| InvalidAlgorithmParameterException | IOException e) {

					System.out.println(e.getMessage());
				}
				System.out.println("Encrypted!");
			} else if (args[0].equals("-D")) {
				try {
					decrypt(password, args[1], args[2]);
				} catch (InvalidKeyException | NoSuchAlgorithmException
						| InvalidKeySpecException | NoSuchPaddingException
						| InvalidAlgorithmParameterException
						| IllegalBlockSizeException | BadPaddingException
						| IOException e) {
					System.out.println(e.getMessage());
				}
				System.out.println("Decrypted!");
			}
		}
	}
}
