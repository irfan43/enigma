//enigma v1.2 Network Spec

//handshake to generate secret
	TODO document this
//generate AES from Secret KEY
	<send param
	>get param
//verify
	<Random String A (Encrypted) random long
	>Random String B (Encrypted) #these are used to confirm signatures as unique and prevent replay attacks
	<Sign(A+B)
case Commands.RegistrationCommand ->
	RGS
	username:"<username>"
	password:"<passwordHash>"  # SHA256("Enigma_Turing" + password + "Turing_Enigma")
	publicKey:"Base64publickeyencoded"
	regCode:"code"
	sign:"Base64Sign" #sign( A + "username" + "<passwordHash>" + reg_code + publickey + A) //base 64 and utf8 encoding

Server stores sha256("Turing_<username>_Storage" + passwordHash + "Turing_<username>_Storage" + Base64publickeyencoded)

case Commands.LoginCommand  ->
	request
		Login
		username:"<username>"
		password:"<passwordHash>" # SHA256("Enigma_Turing" + password + "Turing_Enigma")
		publickey:"Base64publickeyencoded"
		sign:"Base64Sign" #sign(A + "publickey" + password + username + A)
	returns
		good | BAD HEADER / USERNAME_EXISTS / SERVER_ERROR

case Commands.GetPacketCommand ->
	request
		Get PACKET

	return
		good | BAD Illegal stat
	#this is a blocking command
case Commands.SendPacketCommand >
	request
		send PACKET

		< [EnigmaPacket]
	return
		good | BAD Illegal state |

case Commands.LogoutCommand ->
	request
		Logout
	return
		goodbye
	disconects
case Commands.GetHistoryCommand ->
	request
		Get HISTORY
	return
		good | bad state
case Commands.GetUserPublicKeyCommand ->
	request
		GET USER_PUBLICKEY
		searchUsername:"<search_Username>"
		sign: sign(A + search_Username + A)
	return
		good | BAD sign
		publickey:"<username>" | DOES_NOT_EXIST

case Commands.GetUsernameCommand ->
	request
		GET USERNAME
		searchPublicKey: <B64encoded public key>
		sign: sign(A + searchPublicKeyB64 + A)
	return
		good | Bad sign
		username:"<username>" | DOES_NOT_EXIST
