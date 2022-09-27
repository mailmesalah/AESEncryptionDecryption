
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES128 {
	public static void encrypt(String key1, String key2, String inputFile,
			String outputFile) {
		try {
			IvParameterSpec iv = new IvParameterSpec(key2.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key1.getBytes("UTF-8"),
					"AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			byte[] encrypted = cipher.doFinal(Files.readAllBytes(Paths
					.get(inputFile)));
			Files.write(Paths.get(outputFile), encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void decrypt(String key1, String key2, String inputFile,
			String outputFile) {
		try {
			IvParameterSpec iv = new IvParameterSpec(key2.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key1.getBytes("UTF-8"),
					"AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Files.readAllBytes(Paths
					.get(inputFile)));
			Files.write(Paths.get(outputFile), original);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void main(String[] args) {

		String key1 = "Bar12345Bar12341"; // 128 bit key
		String key2 = "ThisIsASecretKe1";
		
		System.out.println("AES 128");
		
		if (args.length == 3) {
			if (args[0].equals("-E")) {
				encrypt(key1, key2, args[1], args[2]);
				System.out.println("Encrypted!");
			} else if (args[0].equals("-D")) {
				decrypt(key1, key2, args[1], args[2]);
				System.out.println("Decrypted!");
			}			
		}
	}
}
