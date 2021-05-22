package org.dragonservers.enigma;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EnigmaPacketFactory{

	private static final List<EnigmaPacket> InboundQueue = new ArrayList<>();
	private static final List<EnigmaPacket> OutboundQueue = new ArrayList<>();
	private final static Object Inbound_Lock = new Object(),Outbound_Lock = new Object();
	private static boolean done = false;


	public static void QueueOutgoingPacket(EnigmaPacket outgoingPacket) {
		synchronized (Outbound_Lock){
			OutboundQueue.add(outgoingPacket);
		}
	}
	/**<p>function tries to queue the give packet into the processing queue</p>
	 *
	 * @param incomingPacket the packet to place in the packet queue
	 */
	public static void QueueIncomingPacket(EnigmaPacket incomingPacket){
		try {
			if(VerifyToAddr(incomingPacket)) {
				synchronized (Inbound_Lock) {
					InboundQueue.add(incomingPacket);
					done = false;
				}
				EnigmaCLI.backgroundThread.notify();
			}else {
				System.out.println("ERROR:Packet Unsigned or Addressed to someone else");
			}
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			System.out.println("ERROR:Failed to Verify Signature of Packet");
			e.printStackTrace();
		}
	}
	/**<p>verify the packed passed to the function is has our to address</p>
	 * @param testingPacket packet to be tested
	 * @throws NoSuchAlgorithmException if the EnigmaPacket signature is not supported on the client machine
	 * @throws SignatureException if it runs into a error while verifying signature
	 * @throws InvalidKeyException if the packets given key is invalid
	 * @return true if the testingPacket is intend for us
	 */
	private static boolean VerifyToAddr(EnigmaPacket testingPacket) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		return testingPacket.VerifySignature()
				&&Arrays.equals(
				testingPacket.getToAddr().getEncoded(),
				Enigma.OurKeyHandler.GetPublicKey().getEncoded());
	}

	/**<p>
	 * Goes through the packet queue and process them
	 * placing them in the correct Message Queue
	 * </p>
	 *
	 */
	public static void HandleInboundPackets(){
		EnigmaPacket enigmaPacket = null;
		synchronized (Inbound_Lock){
			if (!InboundQueue.isEmpty())
				enigmaPacket = InboundQueue.remove(0);
		}
		if(enigmaPacket != null) {
			try {
				ProcessEnigmaPacket(enigmaPacket);
			} catch (Exception e) {
				//TODO stop ignoring these errors
				System.out.println("Error: While Processing Packet");
			}
		}
	}
	public static boolean HandleOutboundPackets() throws GeneralSecurityException, IOException {
		EnigmaPacket enigmaPacket = null;
		synchronized (Outbound_Lock){
			if(!OutboundQueue.isEmpty())
				enigmaPacket = InboundQueue.remove(0);
		}
		if(enigmaPacket != null){
			Enigma.TuringConnection.SendPacket(enigmaPacket);
		}
		return (enigmaPacket != null);
	}

	/**
	 *
	 * @param enigmaPacket packet to be processed
	 */
	private static void ProcessEnigmaPacket(EnigmaPacket enigmaPacket)
			throws IOException, GeneralSecurityException, ClassNotFoundException {
		byte[] data = enigmaPacket.GetData();

		ByteArrayInputStream bis = new ByteArrayInputStream(data);
		String Command = new String(ReadBlock(bis), StandardCharsets.UTF_8);
		byte[] block = ReadBlock(bis);
		switch (Command){
			case "Text" -> {

				EnigmaFriendManager. receivedMessage(block,enigmaPacket.getFromAddr().getEncoded());
			}
			case "START_KEY_X" -> {
				EnigmaFriendManager.HandleNewIntroductionToken(
						new String(block));
			}
			default -> {
				System.out.println("Unknown Packet Type Received ");
			}
		}
	}
	public static void SendIntroductionToken(String targetUsername, PublicKey friendsPublicKey)
			throws GeneralSecurityException, IOException {
		String token  = EnigmaFriendManager.GetIntroductionToken(targetUsername,friendsPublicKey);
		QueueToken(token,targetUsername);
	}
	public static void SendIntroductionToken(String targetUsername)
			throws GeneralSecurityException, IOException {
		String token = EnigmaFriendManager.GetIntroductionToken(targetUsername);
		QueueToken(token,targetUsername);
	}
	private static void QueueToken(String token,String targetUsername){
		EnigmaPacket ep = new EnigmaPacket(Enigma.OurKeyHandler.GetPublicKey(),
				EnigmaFriendManager.GetPublicKeyFromUsername(targetUsername));
		PushBlockOnPacket(ep,
				"START_KEY_X".getBytes(StandardCharsets.UTF_8));
		PushBlockOnPacket(ep,
				token.getBytes(StandardCharsets.UTF_8));
		QueueOutgoingPacket(ep);
	}
	private static void PushBlockOnPacket(EnigmaPacket ep, byte[] data){
		ep.update(ByteBuffer
				.allocate(4)
				.putInt(data.length)
				.array());
		ep.update(data);
	}
	private static byte[] ReadBlock(InputStream is) throws IOException {
		byte[] lenEncoded = new byte[4];
		is.read(lenEncoded);
		int len = ByteBuffer.wrap(lenEncoded).getInt();
		byte[] rtr = new byte[len];
		is.read(rtr);
		return rtr;
	}

}
