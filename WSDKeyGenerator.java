import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A tool for creating a double length tripleDES working key
 * @author rmurali
 *
 */
public class WSDKeyGenerator {

	public static byte[] h2b(String hex) {
		if ((hex.length() & 0x01) == 0x01)
			throw new IllegalArgumentException();
		byte[] bytes = new byte[hex.length() / 2];
		for (int idx = 0; idx < bytes.length; ++idx) {
			int hi = Character.digit((int) hex.charAt(idx * 2), 16);
			int lo = Character.digit((int) hex.charAt(idx * 2 + 1), 16);
			if ((hi < 0) || (lo < 0))
				throw new IllegalArgumentException();
			bytes[idx] = (byte) ((hi << 4) | lo);
		}
		return bytes;
	}

	public static String b2h(byte[] bytes) {
		char[] hex = new char[bytes.length * 2];
		for (int idx = 0; idx < bytes.length; ++idx) {
			int hi = (bytes[idx] & 0xF0) >>> 4;
			int lo = (bytes[idx] & 0x0F);
			hex[idx * 2] = (char) (hi < 10 ? '0' + hi : 'A' - 10 + hi);
			hex[idx * 2 + 1] = (char) (lo < 10 ? '0' + lo : 'A' - 10 + lo);
		}
		return new String(hex);
	}

	public static String binaryToHex(String bin) {

		StringBuilder hex = new StringBuilder();
		for (int i = 0; i < bin.length();) {
			hex.append(Integer.toHexString(Integer.parseInt(
					bin.substring(i, i + 4), 2)));
			i += 4;
			if (i >= bin.length())
				break;

		}
		return hex.toString();
	}

	/**
	 * converts a string of bits to a byte array
	 * 
	 * @param bin
	 * @return
	 */
	public static byte[] binaryStringToByte(String bin) {

		byte[] retVal = new byte[16];
		int j = 0;

		for (int i = 0; i < bin.length();) {
			String substr = bin.substring(i, i + 8);
			int val = 0;
			int sign = 1;

			if (substr.charAt(0) == '1')
				sign = -1;

			for (int k = 1; k < substr.length(); k++) {
				System.out.println("K is " + k);
				if (substr.charAt(k) == '1') {
					val += Math.pow(2, (8 - k - 1));

					System.out.println("Value is " + val);
				} else {
					System.out.println("val is " + 0);
				}

			}

			i += 8;
			val = sign * val;
			retVal[j] = (byte) (val);
			j++;
			if (i >= bin.length())
				break;

		}
		return retVal;
	}

	public void generate() throws Exception {

		System.out.print("Custodian 1 Enter Hex String:");
		String hexString1 = System.console().readLine();
		System.out.print("Custodian 2 Enter Hex String:");
		String hexString2 = System.console().readLine();

		//String hexString1 = "76D354759EB613D6F480BFD37A072AD9";
		//String hexString2 = "C19740C7D5F10B1F0DCE6B8FD03DB994";

		String binaryRep1 = convertHexStringToBinaryString(hexString1);
		String binaryRep2 = convertHexStringToBinaryString(hexString2);
		// String binaryRep3 = convertHexStringToBinaryString(hexString3);

		// print KCV of individual keys
		String zeroBlock = "000000000000000000000000000000000000000000000000";

		String key = WSDKeyGenerator.xORBinaryStrings(binaryRep1, binaryRep2);
		String hexKey = binaryToHex(key);
		String hexKey1 = binaryToHex(binaryRep1);
		String hexKey2 = binaryToHex(binaryRep2);
		

		byte[] CDRIVES = h2b(hexKey);
		byte[] myKey = null;
		if (CDRIVES.length == 16) {
			myKey = new byte[24];
			System.arraycopy(CDRIVES, 0, myKey, 0, 16);
			System.arraycopy(CDRIVES, 0, myKey, 16, 8);
		}

		byte[] CDRIVES1 = h2b(hexKey1);
		byte[] myKey1 = null;
		if (CDRIVES.length == 16) {
			myKey1 = new byte[24];
			System.arraycopy(CDRIVES1, 0, myKey1, 0, 16);
			System.arraycopy(CDRIVES1, 0, myKey1, 16, 8);
		}

		byte[] CDRIVES2 = h2b(hexKey2);
		byte[] myKey2 = null;
		if (CDRIVES.length == 16) {
			myKey2 = new byte[24];
			System.arraycopy(CDRIVES2, 0, myKey2, 0, 16);
			System.arraycopy(CDRIVES2, 0, myKey2, 16, 8);
		}

		SecretKey keySpec = new SecretKeySpec(myKey, "DESede");

		// print KCV of combined key
		Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		byte[] cipherText = cipher.doFinal(h2b(zeroBlock));

		String kcv = b2h(cipherText);
		System.out.println("KCV of combined key is " + kcv.substring(0, 6));

		SecretKey keySpec1 = new SecretKeySpec(myKey1, "DESede");
		cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec1);
		byte[] cipherText1 = cipher.doFinal(h2b(zeroBlock));

		String kcv1 = b2h(cipherText1);
		System.out.println("KCV of key component 1 is " + kcv1.substring(0, 6));

		SecretKey keySpec2 = new SecretKeySpec(myKey2, "DESede");
		cipher = Cipher.getInstance("DESede");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec2);
		byte[] cipherText2 = cipher.doFinal(h2b(zeroBlock));

		String kcv2 = b2h(cipherText2);
		System.out.println("KCV of key component 2 is " + kcv2.substring(0, 6));

		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(null, null);
		keyStore.setKeyEntry("WSD", keySpec, "password".toCharArray(), null);
		keyStore.store(new FileOutputStream("output.jceks"),
				"password".toCharArray());

		keyStore.load(new FileInputStream("output.jceks"),
				"password".toCharArray());
		Key loadedKey = keyStore.getKey("WSD", "password".toCharArray());
		System.out.println(loadedKey.toString());
		System.out.println(loadedKey.getAlgorithm());

		String iv = "00000000";

		// print KCV of combined key
		cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, loadedKey,
				new IvParameterSpec(iv.getBytes()));
		cipherText = cipher.doFinal("TESTTEST".getBytes());

		cipher = Cipher.getInstance("DESede/CBC/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, loadedKey,
				new IvParameterSpec(iv.getBytes()));
		String plainText = new String(cipher.doFinal(cipherText));
		System.out.println(plainText);

	}

	public static String hexToBinary(String hex) {
		int i = Integer.parseInt(hex, 16);
		String bin = Integer.toBinaryString(i);
		return bin;
	}

	public static byte[] hexStringToByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int index = i * 2;
			int v = Integer.parseInt(s.substring(index, index + 2), 16);
			b[i] = (byte) v;
		}
		return b;
	}

	private static String prependWithZeros(String input) {
		String result = input;
		if (input.length() == 2) {
			result = "00" + input;
		} else if (input.length() == 3) {
			result = "0" + input;
		} else if (input.length() == 1) {
			result = "000" + input;
		}
		return result;
	}

	public static String convertHexStringToBinaryString(String hex) {
		StringBuffer binary = new StringBuffer();

		for (int i = 0; i < hex.length(); i++) {

			binary.append(prependWithZeros(hexToBinary(hex.substring(i, i + 1))));
		}

		return binary.toString();
	}

	public static String xORBinaryStrings(String binaryString1,
			String binaryString2) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < binaryString1.length(); i++) {
			Integer first = Integer.valueOf(binaryString1.substring(i, i + 1));
			Integer second = Integer.valueOf(binaryString2.substring(i, i + 1));
			Integer xoredResult = first.intValue() ^ second.intValue();
			result.append(xoredResult.toString());
		}
		return result.toString();
	}

	public static void main(String[] args) {
		try {

			WSDKeyGenerator generator = new WSDKeyGenerator();
			generator.generate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

