package org.dragonservers.enigmaclient;

import org.dragonservers.enigma.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;


public class TextMessage implements Serializable {


	public byte[] FromAddr;
	public byte[] ToAddr;
	public long send_time;
	public String messageData;
	public byte[] sign;

	//TODO move this to byteArrayInputStream

	/**
	 * @javadoc This function holds a signed text message from one user to another
	 *
	 * @param data is the text of the message
	 * @param toAddr is the destination Address of the message
	 * @param fromAddr is the Origin Address of the message
	* */
	public TextMessage(String data, byte[] toAddr, byte[] fromAddr, PrivateKey pk)
			throws GeneralSecurityException, IOException {
		init(data,toAddr,fromAddr,pk, System.currentTimeMillis());
	}

	private void init(String data, byte[] toAddr, byte[] fromAddr, PrivateKey pk, long time)
			throws GeneralSecurityException, IOException {
		ToAddr = toAddr;
		FromAddr = fromAddr;
		messageData = data;
		send_time = time;
		SignData(pk);
	}
	public TextMessage(byte[] EncodedBinary) throws IOException {
		ByteArrayInputStream bis = new ByteArrayInputStream(EncodedBinary);
		ToAddr = EnigmaBlock.ReadBlock(bis);
		FromAddr= EnigmaBlock.ReadBlock(bis);
		messageData = new String( EnigmaBlock.ReadBlock(bis), StandardCharsets.UTF_8 );

		byte[] timeEnc = EnigmaBlock.ReadBlock(bis);
		send_time = ByteBuffer.wrap(timeEnc).getLong();
		sign = EnigmaBlock.ReadBlock(bis);
	}



	public boolean verify() throws GeneralSecurityException, IOException {
		PublicKey pbk = EnigmaKeyHandler.PublicKeyFromEnc(FromAddr);
		return verify(pbk);
	}
	public boolean verify(PublicKey publicKey) throws GeneralSecurityException, IOException {
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initVerify(publicKey);
		sgn.update(signingData());
		return sgn.verify(sign);
	}
	public byte[] getBinary() throws IOException {
		byte[] signedData = signingData();
		ByteArrayOutputStream bos = new ByteArrayOutputStream(
				signedData.length + getBlockLength(sign));
		bos.write(signedData);
		EnigmaBlock.WriteBlock(bos,sign);
		return bos.toByteArray();
	}
	private void SignData(PrivateKey privateKey) throws GeneralSecurityException, IOException {
		byte[] signing_data = signingData();
		Signature sgn = Signature.getInstance("SHA256withRSA");
		sgn.initSign(privateKey);
		sgn.update(signing_data);
		sign = sgn.sign();
	}

	private byte[] signingData() throws IOException {
		byte[] sendTimeEnc = ByteBuffer.allocate(8).putLong(send_time).array();
		ByteArrayOutputStream baos = new ByteArrayOutputStream(
				getBlockLength(ToAddr)
				+ getBlockLength(FromAddr)
				+ getBlockLength(messageData.getBytes(StandardCharsets.UTF_8))
				+ getBlockLength(sendTimeEnc)
				);

		EnigmaBlock.WriteBlock(baos,ToAddr);
		EnigmaBlock.WriteBlock(baos,FromAddr);
		EnigmaBlock.WriteBlock(baos,messageData.getBytes(StandardCharsets.UTF_8));
		EnigmaBlock.WriteBlock(baos,sendTimeEnc);
		return baos.toByteArray();
	}
	private int getBlockLength(byte[] data){
		return data.length + 4;
	}

}
