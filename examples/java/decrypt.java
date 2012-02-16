import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

import de.meetr.hdr.castle_crypt.CastleCrypt;

public class Blubb {
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// Not recommended, provide your own IV!
		CastleCrypt cc = new CastleCrypt();
		
		// Load private key
		File f = new File("test_privateKey");
		byte[] buffer = new byte[(int) f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		cc.setPrivateKey(buffer);
		
		// Load encrypted data
		f = new File("testfile_short");
		buffer = new byte[(int) f.length()];
		in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		
		// Decrypt
		byte[] decrypted = cc.decrypt(buffer);
		// print
		System.out.println(new String(decrypted));
	}
}
