Single block
	first 4byte Denote length of the block (Unencrypted as it would be know and could lead to vulnerabilities )
	Binary data
//todo possible addition of jar files downloads for newer version


//Headers first line of any request should follow the format


[enigma \ 1.00]

List of Gets
-Get PublicKey
		GET PBK
	Returns
		[Server PublicKey]

-Registration
		[ENC]
		[RGS]
		[registration-code:"aczs-wids-asdi-qwed"
		Username:"<Username>"
		Password:"<password-hash>"
		PublicKey:[PublicKey]
		sha256:[hash]]
		//TODO Randomize input to make reversing key difficult

	Returns
		Success Code / Error Code
		//GOOD
		BAD HASH
		BAD CODE
		BAD USERNAME
		BAD PBK
		CUR PBK  //corrupted
-Get Session ID
		ENC
		[GET SESID
		Username:"<Username>"
		PublicKey:[PublicKey]
		Password:"<password-hash>" //todo change later to send hash of the HASH
		Expires:<UTC TIME> //not required]
	return
		GOOD / Bad Credential // depending on if the
		SessionID:"" //64 Characters upper and lower case random string
		Expiry:"" //UTC time of expiry generally 3600 seconds from request

-Get Inbox Available
		ENC
		[GET INBOX
		SessionID:""]
	return
		["GOOD"]
		[number of packets available
		list of first 64 packets available to you]
		//note not that actual packet just the id of the packet and the from addresses
		//PacketID-32-Char+PublicKeyEnc
		//TODO add options to filter by username/PBK
-Get Packet
	ENC
	GET PACKET
	PacketID:"ID"
	SessionID:"sessionid"
returns
	GOOD / BAD Credential / BAD PacketID
	[PACKET DATA]

-Send PACKET
	ENC

List of commands
-registration
-Check Registration //follow with get session id
-Login, get session id //includes request to get expiry date of the session
-Get Inbox Available
-Get Packet
-Send Packet
-Logout Session
-Get History  //ip login history

//later
-set online //online away busy offline // this automaticall goes to offline after 1min
-configure
	-set status
	-get status

	-set dp
	-get dp


any Packet send from a user a to b



Network Block
Unencrypted block first 4 bytes length followed by Data

Encrypted block first 4 bytes Unencrypted length
followed by data

Name:Magic
SessionID:Purple
Color:alpha24
Username:pickles
Apple:true
Organisation:none
MagicApple:nothingPresent
Bears:12
Cookie:none
Dogs:dislike
Cats:Like
