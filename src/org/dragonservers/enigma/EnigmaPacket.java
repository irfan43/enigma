package org.dragonservers.enigma;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import static org.dragonservers.enigma.EnigmaBlock.*;

public class EnigmaPacket implements Serializable {
	private final  PublicKey FromAddr,ToAddr;
	private byte[] Data;
	private byte[] DataSignature;
	private final boolean signed;
	public byte[] EncodedBinary;
	//todo rewrite this
	public EnigmaPacket(byte[] block)
			throws IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		EncodedBinary =  block.clone();
		ByteArrayInputStream bis = new ByteArrayInputStream(block);
		byte[] FromAddrEnc = ReadBlock(bis);
		byte[] ToAddrEnc = ReadBlock(bis);
		Data = ReadBlock(bis);
		DataSignature = ReadBlock(bis);
		signed = true;

		FromAddr = EnigmaKeyHandler.RSAPublicKeyFromEnc(FromAddrEnc);
		ToAddr = EnigmaKeyHandler.RSAPublicKeyFromEnc(ToAddrEnc);
	}
	public EnigmaPacket(PublicKey fromAddr, PublicKey toAddr) {
		FromAddr = fromAddr;
		ToAddr = toAddr;
		Data = new byte[0];
		signed = false;
	}

	public void update(byte[] data) throws IOException {
		if(signed)
			throw new IllegalArgumentException("Updating Signed Packet");
		ByteArrayOutputStream tmp = new ByteArrayOutputStream(Data.length + data.length);
		tmp.write(Data);
		tmp.write(data);
		Data = tmp.toByteArray();
	}


	//Get the Binary to send
	public byte[] GetBinary(PrivateKey ppk)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException {
		if(signed)
			throw new IllegalArgumentException("Signing Signed Packet");
		byte[] FromAddrEnc = FromAddr.getEncoded();
		byte[] ToAddrEnc = ToAddr.getEncoded();
		DataSignature = GenerateSignature(ppk);
		ByteArrayOutputStream baos = new ByteArrayOutputStream(
				FromAddrEnc.length + 4 +
					ToAddrEnc.length + 4 +
					Data.length + 4 +
					DataSignature.length + 4
		);
		WriteBlock(baos,FromAddrEnc);
		WriteBlock(baos,ToAddrEnc);
		WriteBlock(baos,Data);
		WriteBlock(baos,DataSignature);
		return baos.toByteArray();
	}
	private byte[] GenerateSignature(PrivateKey ppk)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(ppk);
		sgn.update(ToAddr.getEncoded());
		sgn.update(Data);
		return sgn.sign();
	}
	public boolean VerifySignature()
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify( FromAddr );
		sgn.update(ToAddr.getEncoded());
		sgn.update(Data);
		return sgn.verify(DataSignature);
	}
	public byte[] GetSignature(){
		return DataSignature;
	}
	public byte[] GetData(){
		return Data;
	}
	public PublicKey getFromAddr() {
		return FromAddr;
	}
	public PublicKey getToAddr(){
		return ToAddr;
	}
}
