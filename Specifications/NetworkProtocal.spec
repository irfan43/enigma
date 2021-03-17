Single block
	first 4byte Denote length of the block (Unencrypted as it would be know and could lead to vulnerabilities )
	Binary data

// > denotes communication from Client to server
// < denotes communication from server to Client
// * is encrypt blocks

registration
>["RGS"]
>[Client Public Key]
<[Server Public Key]
>[Sign UP Code*]
<[Success code*] "200GC" "403BC"
>[Username*]
<[Awk + Success code]
>[Password Hash*]
<[Awk + Success Code]
>[Username #signiture*]
>[Sign Up Code #signiture*]
