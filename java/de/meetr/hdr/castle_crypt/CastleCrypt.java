package de.meetr.hdr.castle_crypt;

/*******************************************************************************
 * This file is part of CastleCrypt
 *******************************************************************************
 *
 * (C) Copyright 2012, Thomas Rebele <rebele@in.tum.de>
 * (C) Copyright 2012, Joseph Wessner <castleCrypt@hdr.meetr.de>
 *
 * CastleCrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; If not,
 * see <http://www.gnu.org/licenses/>.
 *
 *******************************************************************************
 */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CastleCrypt provides an easy to use interface for public-/private-Key de-/encryption.
 * CastleCrypt is available for JAVA and PHP.
 * 
 * @author Thomas Rebele <rebele@in.tum.de>
 * @author Joseph Wessner <castleCrypt@hdr.meetr.de>
 */
public class CastleCrypt {
	/**
	 * PrivateKey used for decryption
	 */
	private RSAPrivateKey privateKey;
	/**
	 * PublicKey used for encryption
	 */
	private RSAPublicKey publicKey;
	
	/**
	 * keySize in Byte (256 Byte = 2048 Bit), CastleCrypt supports only 2048 Bit keySize atm
	 */
	private final int keySize = 256;
	/**
	 * keySize in Byte for AES keys (16 Byte = 128 Bit), CastleCrypt supports only 128 Bit AES keys atm
	 */
	private final int keySizeAES = 16;
	
	/**
	 * Default IV, which is used if no other IV is given in constructor
	 */
	private static final byte[] defaultIVBytes = {
			(byte) 0xd6, (byte) 0x56, (byte) 0x3d, (byte) 0xfc,
			(byte) 0x82, (byte) 0x78, (byte) 0x58, (byte) 0xb2,
			(byte) 0xa5, (byte) 0xda, (byte) 0x5a, (byte) 0xc7,
			(byte) 0xdd, (byte) 0xb0, (byte) 0xf0, (byte) 0xb5
	};	
	/**
	 * IV used for AES de-/encryption
	 */
	private final IvParameterSpec defaultIV;
	
	/**
	 * If this bit is set, hybrid encrption is used.
	 * BitMask for checking the first bit of a byte (1 << 7)
	 */
	private static final int methodMask = 0x80;
	
	/**
	 * the key length field of the output is left-shifted by this constant (or right-shifted for input)
	 */
	private static final int keyLengthMultiplier = 5;
	/**
	 * constant for better code reading; don't change
	 */
	private static final int keyLengthFieldSize = 1;
	
	/**
	 * Constructor which uses CastleCrypt's default initializationVector for AES.
	 * It is recommended to provide your own initializationVector.
	 * 
	 * @deprecated
	 */
	public CastleCrypt() {
		this.defaultIV = new IvParameterSpec(CastleCrypt.defaultIVBytes);
	}
	
	/**
	 * Default constructor
	 * 
	 * @param initializationVector
	 */
	public CastleCrypt(byte[] initializationVector) {
		this.defaultIV = new IvParameterSpec(initializationVector);
	}
	
	/**
	 * Set privateKey (used for decryption)
	 * 
	 * If you want to use a private key from DER-file you have to read the file first, e.g.
	 * 
	 * File privKeyFile = new File("path/to/private_key.der");
	 * byte[] buffer = new byte[(int) privKeyFile.length()];
	 * DataInputStream in = new DataInputStream(new FileInputStream(privKeyFile));
	 * in.readFully(buffer);
	 * in.close();
	 * 
	 * castleCrypt.setPrivateKey(buffer);
	 * 
	 * @param key private key as byteArray
	 * @return true on success
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public boolean setPrivateKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(key));
		return this.setPrivateKey(privateKey);
	}
	
	/**
	 * Set privateKey (used for decryption)
	 * 
	 * @param key
	 * @return true on success
	 */
	public boolean setPrivateKey(RSAPrivateKey key) {
		this.privateKey = key;
		return (this.privateKey != null);
	}
	
	/**
	 * Set publicKey (used for encryption)
	 * 
	 * If you want to use a public key from DER-file you have to read the file first, e.g.
	 * 
	 * File pubKeyFile = new File("path/to/public_key.der");
	 * byte[] buffer = new byte[(int) pubKeyFile.length()];
	 * DataInputStream in = new DataInputStream(new FileInputStream(pubKeyFile));
	 * in.readFully(buffer);
	 * in.close();
	 * 
	 * castleCrypt.setPublicKey(buffer);
	 * 
	 * @param key public key as byteArray
	 * @return true on success
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public boolean setPublicKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(key));
		return this.setPublicKey(publicKey);
	}
	
	/**
	 * Set publicKey (used for encryption)
	 * 
	 * @param key
	 * @return true on success
	 */
	public boolean setPublicKey(RSAPublicKey key) {
		this.publicKey = key;
		return (this.publicKey != null);
	}
	
	/**
	 * Encrypt data with public key
	 * 
	 * @param data data to encrypt
	 * @return encrypted data
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] encrypt(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] encryptedData = {};
		byte prefix = 0;
		
		if (data.length < this.keySize - 11) {
			// We can use RSA without AES
			encryptedData = this.doRSAEncryption(data);
		} else {
			// data is too big, use hybrid method with AES
			// Set hybrid mode bit
			prefix |= CastleCrypt.methodMask;
			
			// generate AES key
			byte[] aesKey = this.getRandomKey();
			
			// encrypt AES key with RSA
			byte[] encryptedKey = this.doRSAEncryption(aesKey);
			
			// encrypt data with AES
			byte[] aesCrypted = this.doAESEncryption(aesKey, data);
			
			// calculate key length
			byte keyLength = (byte) (encryptedKey.length >> CastleCrypt.keyLengthMultiplier);
		
			encryptedData = new byte[CastleCrypt.keyLengthFieldSize + encryptedKey.length + aesCrypted.length];
			
			encryptedData[0] = keyLength;
			System.arraycopy(encryptedKey, 0, encryptedData, CastleCrypt.keyLengthFieldSize, encryptedKey.length);
			System.arraycopy(aesCrypted, 0, encryptedData, (CastleCrypt.keyLengthFieldSize + encryptedKey.length), aesCrypted.length);
		}
		
		byte[] result = new byte[1 + encryptedData.length];
		result[0] = prefix;
		System.arraycopy(encryptedData, 0, result, 1, encryptedData.length);
		
		return result;
	}
	
	/**
	 * Decrypt data with private key
	 * 
	 * @param data data to decrypt
	 * @return decrypted data
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] decrypt(byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] decryptedData = {};
		byte prefix = data[0];
		
		byte[] cryptedData = new byte[data.length - 1];
		System.arraycopy(data, 1, cryptedData, 0, cryptedData.length);
		
		if ((prefix & CastleCrypt.methodMask) == CastleCrypt.methodMask) {
			// hybrid mode was used for encryption
			// get AES key length
			int keyLengthInBytes = cryptedData[0] << CastleCrypt.keyLengthMultiplier;
			
			// get AES key
			byte[] encryptedKey = new byte[keyLengthInBytes];
			System.arraycopy(cryptedData, CastleCrypt.keyLengthFieldSize, encryptedKey, 0, keyLengthInBytes);
			byte[] key = this.doRSADecryption(encryptedKey);
			
			// decrypt data
			byte[] aesData = new byte[cryptedData.length - keyLengthInBytes - CastleCrypt.keyLengthFieldSize];
			System.arraycopy(cryptedData, (CastleCrypt.keyLengthFieldSize + keyLengthInBytes), aesData, 0, aesData.length);
			decryptedData = this.doAESDecryption(key, aesData);
		} else {
			// only RSA encryption was used
			decryptedData = this.doRSADecryption(cryptedData);
		}
		
		return decryptedData;
	}
	
	/**
	 * Encrypt data with this.publicKey (Uses RSA only)
	 * 
	 * @param data data to encrypt
	 * @return encrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] doRSAEncryption(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
		
		byte[] crypted = cipher.doFinal(data);
		return crypted;
	}
	
	/**
	 * Decrypt data with this.privateKey (Uses RSA only)
	 * 
	 * @param data data to decrypt
	 * @return decrypted data
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] doRSADecryption(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
		
		byte[] crypted = cipher.doFinal(data);
		return crypted;
	}
	
	/**
	 * Get a random byteArray of default size (this.keySizeAES).
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] getRandomKey() throws NoSuchAlgorithmException {
		return this.getRandomKey(this.keySizeAES);
	}
	
	/**
	 * Get a random byteArray of given size.
	 * 
	 * @param size size of byteArray (in Byte)
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] getRandomKey(int size) throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(size << 3); // convert byte to bit
		byte[] key = kg.generateKey().getEncoded();
		return key;
	}
	
	/**
	 * Encrypt data with key. (Uses AES only)
	 * 
	 * This method uses AES-192 with CBC
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] doAESEncryption(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// load key
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		// load cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, this.defaultIV);
		// encrypt
		byte[] crypted = cipher.doFinal(data);
		return crypted;
	}
	
	/**
	 * Decrypt data with key. (Uses AES only)
	 * 
	 * This method uses AES-192 with CBC
	 * 
	 * @param key
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] doAESDecryption(byte[] key, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// load key
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		// load cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, this.defaultIV);
		// decrypt
		byte[] crypted = cipher.doFinal(data);
		return crypted;
	}
}
