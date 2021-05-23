package org.dragonservers.enigma;

import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;


public class EnigmaMessages implements Serializable {


	private transient String LastRender;
	private transient String[] LastRenderArray;
	private final byte[] FriendsPublicKey;
	private final String FUsername;
	private final HashMap<Long, TextMessage> chat_log;
	private final HashMap<Long, TextMessage> chat_log_latest;

//TODO add group message option
	public EnigmaMessages(String friendsUsername, PublicKey friendsPublicKey) {
		FUsername = friendsUsername;
		FriendsPublicKey = friendsPublicKey.getEncoded();
		chat_log_latest = new HashMap<>();
		chat_log = new HashMap<>();
	}
	public byte[] SendMessage(String msg, PrivateKey ppk) throws GeneralSecurityException, IOException {
		TextMessage toSend = new TextMessage( msg,FriendsPublicKey, Enigma.OurKeyHandler.GetPublicKey().getEncoded(),Enigma.OurKeyHandler.GetPrivateKey() );
		synchronized (this) {
			chat_log.put(toSend.send_time, toSend);
			chat_log_latest.put(toSend.send_time, toSend);
		}
		return toSend.getBinary();
	}
	public boolean PutMessage(byte[] msg_bin) throws GeneralSecurityException, IOException {
		TextMessage recvd = new TextMessage(msg_bin);
		boolean valid;
		if(!Arrays.equals(recvd.FromAddr,FriendsPublicKey))
			throw new IllegalArgumentException("MESSAGE BAD FROM ADDRESS");
		if(!Arrays.equals(recvd.ToAddr, Enigma.OurKeyHandler.GetPublicKey().getEncoded()))
			throw new IllegalArgumentException("MESSAGE BAD TO ADDRESS");
		valid = recvd.verify();
		if (valid)
			synchronized (this) {
				chat_log.put(recvd.send_time, recvd);
				chat_log_latest.put(recvd.send_time, recvd);
			}
		return valid;
	}
	public String GetRendered(int lines){
		if(LastRender == null){
			reRender(lines);
		}else if(LastRenderArray.length > lines){
				StringBuilder sb= new StringBuilder();
				for (int i = 0; i < lines; i++) {
					sb.append(LastRenderArray[i]);
				}
				LastRender = sb.toString();
		}else{
			reRender(lines);
		}
		return LastRender;
	}

	public void reRender(int nl) {
		String[] lines = new String[nl];
		List<TextMessage> msgs = Get_latest(nl);
		StringBuilder sb = new StringBuilder();
		for (TextMessage m :msgs) {
			sb.append( GetFormattedMessage(m) );
			sb.append("\n");
		}
		LastRender = sb.toString();
		LastRenderArray = LastRender.split("\n");
	}
	private String GetFormattedMessage(TextMessage msg){
		String FORMAT_TIME = "HH:mm:ss";
		String FORMAT_DATE = "yy-MM-dd";
		String Final_Format = FORMAT_TIME;
		if(msg.send_time > EnigmaTime.GetMilisSinceMidnight()){
			Final_Format = FORMAT_DATE + FORMAT_TIME;
		}
		String formattedTime;

		formattedTime = EnigmaTime.GetFormattedTime(msg.send_time,Final_Format);
		formattedTime = "[" + formattedTime + "]";
		String Username = "UNKNOWN";
		if(Arrays.equals(msg.FromAddr,FriendsPublicKey))
			Username = FUsername;
		else if(Arrays.equals(msg.FromAddr,
				Enigma.OurKeyHandler.GetPublicKey().getEncoded()))
			Username = Enigma.Username;

		return formattedTime + Username + ":" + msg.messageData;
	}
	private List<TextMessage> Get_latest(int n){

		if(n > EnigmaFriendManager.Message_Latest_cache)
			n = EnigmaFriendManager.Message_Latest_cache;

		List<TextMessage> rtr = new ArrayList<>();
		synchronized (this) {
			Long[] s = new Long[chat_log_latest.size()];
			chat_log_latest.keySet().toArray(s);
			Arrays.sort(s);
			//purge from latest
			int to_purge = s.length - EnigmaFriendManager.Message_Latest_cache;
			for (int i = 0; i < (to_purge); i++) {
				chat_log_latest.remove(s[i]);
			}
			if(n > s.length)
				n = s.length;
			for (int i = 0; i < n; i++) {
				rtr.add(chat_log_latest.get(s[i]) );
			}
		}
		return rtr;
	}
}
