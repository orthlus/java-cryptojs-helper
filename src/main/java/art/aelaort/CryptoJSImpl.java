package art.aelaort;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoJSImpl {
	private static final String transformation = "AES/CBC/PKCS7Padding";
	private static final String provider = BouncyCastleProvider.PROVIDER_NAME;
	private static final String algorithm = "AES";
	private static final byte[] saltPrefixB = "Salted__".getBytes(UTF_8);

	public static String decrypt(String dataToDecrypt, String password) {
		Security.addProvider(new BouncyCastleProvider());

		try {
			byte[] passwordBytes = password.getBytes(UTF_8);
			byte[] decodedData = Base64.getDecoder().decode(dataToDecrypt);

			if (!Arrays.equals(saltPrefixB, Arrays.copyOfRange(decodedData, 0, 8))) {
				throw new CryptoJSImplDecryptionException("'Salted__' not found");
			}

			byte[] salt = new byte[8];
			System.arraycopy(decodedData, 8, salt, 0, 8);

			final byte[][] keyAndIV = generateKeyAndIV(salt, passwordBytes);

			Cipher cipher = Cipher.getInstance(transformation, provider);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyAndIV[0], algorithm), new IvParameterSpec(keyAndIV[1]));

			byte[] data = Arrays.copyOfRange(decodedData, 16, decodedData.length);
			byte[] decrypted = cipher.doFinal(data);

			return new String(decrypted);
		} catch (Exception e) {
			throw new CryptoJSImplDecryptionException(e);
		}
	}

	public static String encrypt(String dataToEncrypt, String password) {
		Security.addProvider(new BouncyCastleProvider());

		try {
			byte[] bytesToEncrypt = dataToEncrypt.getBytes(UTF_8);
			byte[] passwordBytes = password.getBytes(UTF_8);

			SecureRandom sr = new SecureRandom();
			byte[] salt = new byte[8];
			sr.nextBytes(salt);

			final byte[][] keyAndIV = generateKeyAndIV(salt, passwordBytes);

			Cipher cipher = Cipher.getInstance(transformation, provider);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyAndIV[0], algorithm), new IvParameterSpec(keyAndIV[1]));

			byte[] encryptedData = cipher.doFinal(bytesToEncrypt);
			byte[] prefixAndSaltAndEncryptedData = new byte[16 + encryptedData.length];

			// Copy prefix (0-th to 7-th bytes)
			System.arraycopy(saltPrefixB, 0, prefixAndSaltAndEncryptedData, 0, 8);
			// Copy salt (8-th to 15-th bytes)
			System.arraycopy(salt, 0, prefixAndSaltAndEncryptedData, 8, 8);
			// Copy encrypted data (16-th byte and onwards)
			System.arraycopy(encryptedData, 0, prefixAndSaltAndEncryptedData, 16, encryptedData.length);

			return Base64.getEncoder().encodeToString(prefixAndSaltAndEncryptedData);
		} catch (Exception e) {
			throw new CryptoJSImplEncryptionException(e);
		}
	}

	private static byte[][] generateKeyAndIV(byte[] salt, byte[] password) throws NoSuchAlgorithmException {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		return generateKeyAndIV(32, 16, 1, salt, password, md5);
	}

	private static byte[][] generateKeyAndIV(int keyLength, int ivLength,
											int iterations, byte[] salt,
											byte[] password, MessageDigest md) {
		int digestLength = md.getDigestLength();
		int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
		byte[] generatedData = new byte[requiredLength];
		int generatedLength = 0;

		try {
			md.reset();

			// Repeat process until sufficient data has been generated
			while (generatedLength < keyLength + ivLength) {

				// Digest data (last digest if available, password data, salt if available)
				if (generatedLength > 0)
					md.update(generatedData, generatedLength - digestLength, digestLength);
				md.update(password);
				if (salt != null)
					md.update(salt, 0, 8);
				md.digest(generatedData, generatedLength, digestLength);

				// additional rounds
				for (int i = 1; i < iterations; i++) {
					md.update(generatedData, generatedLength, digestLength);
					md.digest(generatedData, generatedLength, digestLength);
				}

				generatedLength += digestLength;
			}

			// Copy key and IV into separate byte arrays
			byte[][] result = new byte[2][];
			result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
			if (ivLength > 0)
				result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);

			return result;

		} catch (DigestException e) {
			throw new RuntimeException(e);

		} finally {
			// Clean out temporary data
			Arrays.fill(generatedData, (byte)0);
		}
	}
}
