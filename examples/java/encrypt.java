import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import de.meetr.hdr.castle_crypt.CastleCrypt;

public class Encrypt {
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// Not recommended, provide your own IV!
		CastleCrypt cc = new CastleCrypt();
		
		// Load public key		
		File f = new File("test_publicKey.der");
		byte[] buffer = new byte[(int) f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		cc.setPublicKey(buffer);
		
		// Bytes to encrypt
		String text = "Short Example.";
		byte[] data = text.getBytes();
		
		// Encrypt
		byte[] encrypted = cc.encrypt(data);
		
		// Save to file
		FileOutputStream fos = new FileOutputStream("testfile_short");
		fos.write(encrypted);
		fos.flush();
		fos.close();
		
		// Longer example
		text = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
		data = text.getBytes();
		// Encrypt
		encrypted = cc.encrypt(data);
		// Save to file
		fos = new FileOutputStream("testfile_longer");
		fos.write(encrypted);
		fos.flush();
		fos.close();
	}
}
