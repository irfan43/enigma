package org.dragonservers.enigma;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Message implements Serializable {


	public byte[] FromAddr;
	public byte[] ToAddr;
	public long send_time;
	public String messageData;
	public byte[] sign;

	/**
	 * @javadoc This function holds a signed text message from one user to another
	 *
	 * @param data is the text of the message
	 * @param toAddr is the destination Address of the message
	 * @param fromAddr is the Origin Address of the message
	* */
	public Message(String data, byte[] toAddr, byte[] fromAddr, PrivateKey pk) throws GeneralSecurityException {
		init(data,toAddr,fromAddr,pk, System.currentTimeMillis());
	}

	private void init(String data, byte[] toAddr, byte[] fromAddr, PrivateKey pk, long time) throws GeneralSecurityException{
		ToAddr = toAddr;
		FromAddr = fromAddr;
		messageData = data;
		send_time = time;
		SignData(pk);
	}
	public Message(byte[] EncodedBinary){
		ByteBuffer bb = ByteBuffer.wrap(EncodedBinary);
		int pos = 0;
		send_time = bb.getLong();
		pos += 8;
		ToAddr = getBlock(bb, pos);
		pos += ToAddr.length + 4;
		FromAddr = getBlock(bb,pos);
		pos += FromAddr.length + 4;
		byte[] dateEncoded = getBlock(bb, pos);
		pos += dateEncoded.length + 4;
		messageData = new String( dateEncoded ,StandardCharsets.UTF_8);
		sign = getBlock(bb,pos);
	}
	public boolean verify() throws GeneralSecurityException {
		PublicKey pbk = EnigmaKeyHandler.PublicKeyFromEnc(FromAddr);
		return verify(pbk);
	}
	public boolean verify(PublicKey publicKey) throws GeneralSecurityException{
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(publicKey);
		sgn.update(signingData());
		return sgn.verify(sign);
	}
	public byte[] getBinary(){
		byte[] signedData = signingData();
		ByteBuffer bb = ByteBuffer.allocate(signedData.length + sign.length);
		bb.put(signedData);
		bb.put(sign,signedData.length,sign.length);
		return bb.array();
	}



	private byte[] getBlock(ByteBuffer bb,int pos){
		int len = bb.getInt(pos);
		byte[] data = new byte[len];
		bb.get(data,pos + 4, len);
		return data;
	}

	private void SignData(PrivateKey privateKey) throws GeneralSecurityException{
		byte[] signing_data = signingData();
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(privateKey);
		sgn.update(signing_data);
		sign = sgn.sign();
	}
	private byte[] getAddrBlocks(){
		byte[] toBlock = getBlock(ToAddr);
		byte[] fromBlock = getBlock(FromAddr);
		ByteBuffer bb = ByteBuffer.allocate(toBlock.length + fromBlock.length);
		bb.put(fromBlock);
		bb.put(toBlock,fromBlock.length,toBlock.length);
		return bb.array();
	}
	private byte[] getBlock(byte[] data){
		int len = data.length;
		ByteBuffer bb = ByteBuffer.allocate(4 + data.length);
		bb.putInt(len);
		bb.put(data , 4, data.length);
		return bb.array();
	}
	private byte[] signingData(){
		byte[] header = getAddrBlocks();
		byte[] dataBlock = getBlock(messageData.getBytes(StandardCharsets.UTF_8));
		ByteBuffer bb = ByteBuffer.allocate(8 + header.length + dataBlock.length);
		bb.putLong(send_time);
		bb.put(header,8,header.length);
		bb.put(dataBlock, 8 + header.length,dataBlock.length);
		return bb.array();
	}

}
