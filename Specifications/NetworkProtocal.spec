Single block
	first 4byte Denote length of the block (Unencrypted as it would be know and could lead to vulnerabilities )
	Binary data
//todo possible addition of jar files downloads for newer version


//Headers first line of any request should follow the format


//generic errors
BAD Headers
BAD Server Error
//here bad or good doesn't imply if the request was good, instead it implies if the returned data is good

[enigma \ 1.00]

List of Gets
-Get PublicKey
		GET PBK
	Returns
		[Server PublicKey]
-Registration
		[ENC]
		  [PublicKey ECDH]->
		<-[Server ECDH PublicKey][signature]
		<-["GOOD KEYX"] | ["BAD KEYX"] | ["BAD KEYX SERVER_SIGN_ERROR"]
		[RGS]->
		[
		registration-code:"aczs-wids-asdi-qwed"
		username:"<Username>"
		password:"<password-hash>"
		publickey: PublicKey base64 encoded
		//sha256:[hash]
		]
		//TODO Randomize input to make reversing key difficult

	Returns
		Success Code / Error Code
		GOOD
		BAD HASH
		BAD CODE DOES_NOT_EXIST || INVALID_OR_EXPIRED
		BAD USERNAME NAME_ALREADY_EXIST || INVALID_NAME
		BAD PUBLIC_KEY INVALID_FORMAT || INVALID_KEY_SPEC || KEY_ALREADY_EXIST
		BAD PASSWORD INVALID_FORMAT
-Get Session ID Equivalent to a login request
		ENC
		[GET SESID]
		[
		PublicKey:B64(PublicKey)
		Password:"<password-hash>" //todo change later to send hash of the HASH
		headerUTC: Long encoded base 64 //this is made to string then Binary then placed before the password hash and rehashed
		headerSign:<base 64 signature> //TODO
		]
	return
		GOOD / Bad Credential // depending on if the
		SessionID:"" //64 Characters upper and lower case random string
		Expiry:"" //UTC time of expiry generally 3600 seconds from request

-Get Inbox Available
		ENC
		[
		GET INBOX
		PublicKey:[]
		SessionID:""
		]
	return
		["GOOD"]
		[number of packets available
		list of first 64 packets available to you]
		//note not that actual packet just the id of the packet and the from addresses
		//PacketID-32-Char+PublicKeyEnc
		//TODO add options to filter by username/PBK
-Get Packet
		ENC
		[GET PACKET]
		[
		publickey:B64()
		SessionID:"sessionid"
		]
	returns
		GOOD / BAD Credential / BAD PacketID
		[PACKET DATA]

-Send PACKET
		[ENC]
		[SEND PACKET]
		[
		PublicKey:B64()
		SessionID:""
		]
		[PACKET_DATA]
	return
		GOOD / BAD

-GET USER_PUBLIC_KEY
		[ENC]
		[CMD]
		[
		PublicKey:B64()
		SessionID:""
		Search-Username:""
		]
	return
		GOOD / BAD Cred header etc
		DOES_NOT_EXIST / PublicKey: B64()
-GET USERNAME
		[ENC]
		[CMD]
		[
		PublicKey:B64()
		SessionID:""
		Search-PublicKey:B64()
		]
		return
		GOOD / BAD Cred header etc
		DOES_NOT_EXIST / Username:<string>
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
