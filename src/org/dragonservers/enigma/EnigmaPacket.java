package org.dragonservers.enigma;


import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

public class EnigmaPacket implements Serializable {
	private final  PublicKey FromAddr,ToAddr;
	private byte[] Data;
	private byte[] DataSignature;
	private final boolean signed;
	public byte[] EncodedBinary;
	//todo rewrite this
	public EnigmaPacket(byte[] block) throws IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException {
		EncodedBinary =  block.clone();
		int blockPos = 0;
		byte[] FromAddrEnc = GrabBlock(block,blockPos);
		blockPos += FromAddrEnc.length + 4;
		byte[] ToAddrEnc = GrabBlock(block,blockPos);
		blockPos += ToAddrEnc.length;
		Data = GrabBlock(block,blockPos);
		blockPos += ToAddrEnc.length;
		DataSignature = GrabBlock(block,blockPos);
		signed = true;

		FromAddr = EnigmaKeyHandler.PublicKeyFromEnc(FromAddrEnc);
		ToAddr = EnigmaKeyHandler.PublicKeyFromEnc(ToAddrEnc);
	}
	public EnigmaPacket(PublicKey fromAddr, PublicKey toAddr) {
		FromAddr = fromAddr;
		ToAddr = toAddr;
		Data = new byte[0];
		signed = false;
	}
	private byte[] GrabBlock(byte[] block, int blockPos) throws IllegalArgumentException{
		byte[] lenEnc = Arrays.copyOfRange(block,blockPos, blockPos + 4);
		int len = ByteBuffer.wrap(lenEnc).getInt();
		blockPos += 4;
		if(len < 0 || (len + blockPos) > block.length){
			throw new IllegalArgumentException("invalid length in block");
		}
		return Arrays.copyOfRange(block,blockPos,blockPos + len);
	}
	public void update(byte[] data){
		if(signed)
			throw new IllegalArgumentException("Updating Signed Packet");
		Data = mergeArray(Data,data);
	}

	//Get the Binary to send
	public byte[] GetBinary(PrivateKey ppk) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		if(signed)
			throw new IllegalArgumentException("Signing Signed Packet");
		byte[] Header = mergeArray(getBlock(FromAddr.getEncoded()),getBlock(ToAddr.getEncoded()));
		DataSignature = GenerateSignature(ppk);
		byte[] out =  mergeArray(Header,getBlock(Data));
		return mergeArray(out, DataSignature);
	}

	private byte[] GenerateSignature(PrivateKey ppk) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(ppk);
		sgn.update(ToAddr.getEncoded());
		sgn.update(Data);
		return sgn.sign();
	}
	public boolean VerifySignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify( FromAddr );
		sgn.update(ToAddr.getEncoded());
		sgn.update(Data);
		return sgn.verify(DataSignature);
	}
	private byte[] getBlock(byte[] data){
		byte[] IntEnc = ByteBuffer.allocate(4).putInt(data.length).array();
		return mergeArray(IntEnc,data);
	}
	private byte[] mergeArray(byte[] a, byte[] b ){
		byte[] Array = new byte[a.length + b.length];
		System.arraycopy(a,0,Array,0,a.length);
		System.arraycopy(b,0,Array,a.length,b.length);
		return Array;
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
