#ifndef NTLM_H
#define NTLM_H

#include <Defs.h>

typedef struct _NEGOTIATE_TOKEN {
	CHAR Signature[ 8 ];

	ULONG MessageType;

	ULONG NegotiateFlags;

	struct {
		USHORT DomainLen;
		USHORT DomainMaxLen;
		ULONG  DomainBufferOffset;
	} DomainFields;

	struct {
		USHORT WorkstationLen;
		USHORT WorkstationMaxLen;
		ULONG  WorkstationBufferOffset;
	} WorkstationFields;

	INT64 Version;

	// size is variable
	BYTE Payload[ 1 ];
} NEGOTIATE_TOKEN, *PNEGOTIATE_TOKEN;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
typedef struct _CHALLENGE_TOKEN {
	// 8-byte character array that must contain the ASCII string "NTLMSSP\0"
	CHAR Signature[ 8 ];

	// the message type, must be set to 0x00000002
	ULONG MessageType;

	// a field containing the TargetName information
	struct {
		// size in bytes of TargetName in the payload
		// those 2 values should be equal and have the value described above
		// if target name is a UNICODE_STRING (PWSTR) those values must be multiple of 2
		// if the the NTLMSSP_REQUEST_TARGET flag is not set in NegotiateFlags, indicating a TargetName is not
		// required, the lenght fields must be set to 0
		USHORT TargetNameLen;
		USHORT TargetNameMaxLen;

		// offset in bytes for the TargetName field from the beginning of the CHALLENGE_TOKEN struct
		// if the NTLMSSP_REQUEST_FLAG is not set, still the same offset
		ULONG TargetNameBufferOffset;
	} TargetNameFields;

	// NEGOTIATE structure that contains a set of flags
	ULONG NegotiateFlags;

	// the server challenge
	BYTE ServerChallenge[ 8 ];

	// reserved, all bytes should be set 0
	INT64 Reserved;

	// a field containing the TargetInfo infomation
	// the same concepts as the TargetNameFields struct applies
	// the related flag is NTLMSSP_NEGOTIATE_TARGET_INFO in this case
	// TargetInfoBufferOffset is the offset of a list of AV_PAIR data, no padding between the AV_PAIR structures
	struct {
		USHORT TargetInfoLen;
		USHORT TargetInfoMaxLen;
		ULONG  TargetInfoBufferOffset;
	} TargetInfoFields;

	// VERSION structure, should be populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set
	// otherwise full-0s
	INT64 Version;

	// payload
	// byte array that contains info related the TargetNameFields and TargetInfoFields
	BYTE Payload[ 1 ];
} CHALLENGE_TOKEN, *PCHALLENGE_TOKEN;

//#define AV_PAIR_SIZE( AvPair ) ( AvPair->AvLen + sizeof( USHORT ) + ( 4 - ( AvPair->AvLen + sizeof( USHORT ) ) % 4 ) % 4 )
#define AV_PAIR_SIZE( AvPair ) ( AvPair->AvLen + sizeof( USHORT ) * 2 )

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
typedef struct _AV_PAIR {
	// Information type of the value field, values are referenced in the link above
	USHORT AvId;

	// Number of bytes in the array below
	USHORT AvLen;

	// a byte array of size AvLen
	BYTE Value[ 1 ];
} AV_PAIR, *PAV_PAIR;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b
// part of the AUTHENTICATE token (part of the NT_CHALLENGE_RESPONSE part of the AUTHENTICATE token)
typedef struct _NTLMv2_CLIENT_CHALLENGE {
	// Current version of the challenge response type, must be set to 0x01
	BYTE ResType;

	// Maximum supported version of the challenge response type, must be 0x01
	BYTE HiRespType;

	// reserved should be set to 0x0000
	USHORT Reserved1;

	// reserved should be set to 0x00000000
	ULONG Reserved2;

	// timestamp, represented as the number of 100 naonsecond ticks elapsed since midnight of January 1, 1601
	INT64 Timestamp;

	// the client challenge, chosen by the client can be anything
	// make it random if you want security, or if you don't just want it to be an IoC
	BYTE ChallengeFromClient[ 8 ];

	// reserved should be set to 0x0000...
	INT Reserved3;

	// a byte array that contains a sequence of AV_PAIR structure
	// the next array should not be calculated using sizeof(AV_PAIR) as the size of the structure is not correct
	// because the length is dynamic of size AvLen, so use that number to calculate the next AV_PAIR structure
	AV_PAIR AvPairs[ 1 ];
} NTLMv2_CLIENT_CHALLENGE, *PNTLMv2_CLIENT_CHALLENGE;

// the NtChallengeResponse is 284 bytes in my example while the whole authenticate token length is 452
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80
// part of the AUTHENTICATE token
typedef struct _NT_CHALLENGE_RESPONSE {
	// NtProofStr, well explained at page 432 of "Windows Security Internals" by James Forshaw
	BYTE NtProofStr[ 16 ];

	// the structure defined above, read the explaination from the doc and my comments above
	NTLMv2_CLIENT_CHALLENGE Challenge;
} NT_CHALLENGE_RESPONSE, *PNT_CHALLENGE_RESPONSE;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
typedef struct _AUTHENTICATE_TOKEN {
	// 8-byte character array that must contain the ASCII string "NTLMSSP\0"
	CHAR Signature[ 8 ];

	// the message type, must be set to 0x00000003
	ULONG MessageType;

	// a field containing the LmChallengeResponse information
	// the length should be equals, the theorical offset should be set even if the lengths are 0s
	// the length are 0s if there is no lm response specified
	// there is that same kind of field in the _CHALLENGE_TOKEN struct, i've explained it in more details there
	// point to LM_RESPONSE structure :
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/e3fee6d1-0d93-4020-84ab-ca4dc5405fc9
	// that's what the doc says but from my example I see LmChallengeResponseLen = 24 and BufferOffset to 0
	// so what's what i'm gonna do
	struct {
		USHORT LmChallengeResponseLen;
		USHORT LmChallengeResponseMaxLen;
		ULONG  LmChallengeResponseBufferOffset;
	} LmChallengeResponseFields;

	// same shit as before
	// point to NTLM_RESPONSE structure :
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b88739c6-1266-49f7-9d22-b13923bd8d66
	struct {
		USHORT NtChallengeResponseLen;
		USHORT NtChallengeResponseMaxLen;
		ULONG  NtChallengeResponseBufferOffset;
	} NtChallengeResponseFields;

	// same shit as before
	// the domain or computer name hosting the user account
	// must be encoded in the negotiated character set (WCHAR or CHAR)
	struct {
		USHORT DomainNameLen;
		USHORT DomainNameMaxLen;
		ULONG  DomainNameBufferOffset;
	} DomainNameFields;

	// same shit as before
	// the name of the user to be authenticated
	// must be encoded in the negotiated character set (WCHAR or CHAR)
	struct {
		USHORT UserNameLen;
		USHORT UserNameMaxLen;
		ULONG  UserNameBufferOffset;
	} UserNameFields;

	// same shit as before
	// the name of the computer to which the user is logged on
	// TODO: spoof that? how will the system react?
	struct {
		USHORT WorkstationLen;
		USHORT WorkstationMaxLen;
		ULONG  WorkstationBufferOffset;
	} WorkstationFields;

	// same shit as before
	// the client encrypted random session key
	struct {
		USHORT EncryptedRandomSessionKeyLen;
		USHORT EncryptedRandomSessionKeyMaxLen;
		ULONG  EncryptedRandomSessionKeyBufferOffset;
	} EncryptedRandomSessionKeyFields;

	// NEGOTIATE structure that contains a set of flags
	ULONG NegotiateFlags;

	// VERSION structure, should be populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set
	// otherwise full-0s
	INT64 Version;

	// the MIC
	// i calculate it using my function "CalculateMic"
	BYTE Mic[ 16 ];

	// payload
	// byte array that contains info related the LmChallengeResponseBufferOffset, NtChallengeResponseBufferOffset,
	// DomainNameBufferOffset, UserNameBufferOffset, WorkstationBufferOffset, EncryptedRandomSessionKeyBufferOffset
	BYTE Payload[ 1 ];
} AUTHENTICATE_TOKEN, *PAUTHENTICATE_TOKEN;

typedef struct _SecHandle {
	ULONG_PTR dwLower;
	ULONG_PTR dwUpper;
} SecHandle, *PSecHandle;

typedef SecHandle  CredHandle;
typedef PSecHandle PCredHandle;

typedef SecHandle  CtxtHandle;
typedef PSecHandle PCtxtHandle;

typedef struct _SecBuffer {
	unsigned __LONG32 cbBuffer;
	unsigned __LONG32 BufferType;
	void *            pvBuffer;
} SecBuffer, *PSecBuffer;

typedef struct _SecBufferDesc {
	unsigned __LONG32 ulVersion;
	unsigned __LONG32 cBuffers;
	PSecBuffer        pBuffers;
} SecBufferDesc, *PSecBufferDesc;

typedef LARGE_INTEGER _SECURITY_INTEGER, SECURITY_INTEGER, *PSECURITY_INTEGER;

#ifndef SECURITY_MAC
typedef SECURITY_INTEGER  TimeStamp;
typedef SECURITY_INTEGER *PTimeStamp;
#else
  typedef unsigned __LONG32 TimeStamp;
  typedef unsigned __LONG32 *PTimeStamp;
#endif

typedef WCHAR SEC_WCHAR;
typedef CHAR  SEC_CHAR;

#define SEC_E_INSUFFICIENT_MEMORY _HRESULT_TYPEDEF_(0x80090300)
#define SEC_E_INVALID_HANDLE _HRESULT_TYPEDEF_(0x80090301)
#define SEC_E_UNSUPPORTED_FUNCTION _HRESULT_TYPEDEF_(0x80090302)
#define SEC_E_TARGET_UNKNOWN _HRESULT_TYPEDEF_(0x80090303)
#define SEC_E_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x80090304)
#define SEC_E_SECPKG_NOT_FOUND _HRESULT_TYPEDEF_(0x80090305)
#define SEC_E_NOT_OWNER _HRESULT_TYPEDEF_(0x80090306)
#define SEC_E_CANNOT_INSTALL _HRESULT_TYPEDEF_(0x80090307)
#define SEC_E_INVALID_TOKEN _HRESULT_TYPEDEF_(0x80090308)
#define SEC_E_CANNOT_PACK _HRESULT_TYPEDEF_(0x80090309)
#define SEC_E_QOP_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009030A)
#define SEC_E_NO_IMPERSONATION _HRESULT_TYPEDEF_(0x8009030B)
#define SEC_E_LOGON_DENIED _HRESULT_TYPEDEF_(0x8009030C)
#define SEC_E_UNKNOWN_CREDENTIALS _HRESULT_TYPEDEF_(0x8009030D)
#define SEC_E_NO_CREDENTIALS _HRESULT_TYPEDEF_(0x8009030E)
#define SEC_E_MESSAGE_ALTERED _HRESULT_TYPEDEF_(0x8009030F)
#define SEC_E_OUT_OF_SEQUENCE _HRESULT_TYPEDEF_(0x80090310)
#define SEC_E_NO_AUTHENTICATING_AUTHORITY _HRESULT_TYPEDEF_(0x80090311)
#define SEC_I_CONTINUE_NEEDED _HRESULT_TYPEDEF_(0x00090312)
#define SEC_I_COMPLETE_NEEDED _HRESULT_TYPEDEF_(0x00090313)
#define SEC_I_COMPLETE_AND_CONTINUE _HRESULT_TYPEDEF_(0x00090314)
#define SEC_I_LOCAL_LOGON _HRESULT_TYPEDEF_(0x00090315)
#define SEC_I_GENERIC_EXTENSION_RECEIVED _HRESULT_TYPEDEF_(0x00090316)
#define SEC_E_BAD_PKGID _HRESULT_TYPEDEF_(0x80090316)
#define SEC_E_CONTEXT_EXPIRED _HRESULT_TYPEDEF_(0x80090317)
#define SEC_I_CONTEXT_EXPIRED _HRESULT_TYPEDEF_(0x00090317)
#define SEC_E_INCOMPLETE_MESSAGE _HRESULT_TYPEDEF_(0x80090318)
#define SEC_E_INCOMPLETE_CREDENTIALS _HRESULT_TYPEDEF_(0x80090320)
#define SEC_E_BUFFER_TOO_SMALL _HRESULT_TYPEDEF_(0x80090321)
#define SEC_I_INCOMPLETE_CREDENTIALS _HRESULT_TYPEDEF_(0x00090320)
#define SEC_I_RENEGOTIATE _HRESULT_TYPEDEF_(0x00090321)
#define SEC_E_WRONG_PRINCIPAL _HRESULT_TYPEDEF_(0x80090322)
#define SEC_I_NO_LSA_CONTEXT _HRESULT_TYPEDEF_(0x00090323)
#define SEC_E_TIME_SKEW _HRESULT_TYPEDEF_(0x80090324)
#define SEC_E_UNTRUSTED_ROOT _HRESULT_TYPEDEF_(0x80090325)
#define SEC_E_ILLEGAL_MESSAGE _HRESULT_TYPEDEF_(0x80090326)
#define SEC_E_CERT_UNKNOWN _HRESULT_TYPEDEF_(0x80090327)
#define SEC_E_CERT_EXPIRED _HRESULT_TYPEDEF_(0x80090328)
#define SEC_E_ENCRYPT_FAILURE _HRESULT_TYPEDEF_(0x80090329)
#define SEC_E_DECRYPT_FAILURE _HRESULT_TYPEDEF_(0x80090330)
#define SEC_E_ALGORITHM_MISMATCH _HRESULT_TYPEDEF_(0x80090331)
#define SEC_E_SECURITY_QOS_FAILED _HRESULT_TYPEDEF_(0x80090332)
#define SEC_E_UNFINISHED_CONTEXT_DELETED _HRESULT_TYPEDEF_(0x80090333)
#define SEC_E_NO_TGT_REPLY _HRESULT_TYPEDEF_(0x80090334)
#define SEC_E_NO_IP_ADDRESSES _HRESULT_TYPEDEF_(0x80090335)
#define SEC_E_WRONG_CREDENTIAL_HANDLE _HRESULT_TYPEDEF_(0x80090336)
#define SEC_E_CRYPTO_SYSTEM_INVALID _HRESULT_TYPEDEF_(0x80090337)
#define SEC_E_MAX_REFERRALS_EXCEEDED _HRESULT_TYPEDEF_(0x80090338)
#define SEC_E_MUST_BE_KDC _HRESULT_TYPEDEF_(0x80090339)
#define SEC_E_STRONG_CRYPTO_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009033A)
#define SEC_E_TOO_MANY_PRINCIPALS _HRESULT_TYPEDEF_(0x8009033B)
#define SEC_E_NO_PA_DATA _HRESULT_TYPEDEF_(0x8009033C)
#define SEC_E_PKINIT_NAME_MISMATCH _HRESULT_TYPEDEF_(0x8009033D)
#define SEC_E_SMARTCARD_LOGON_REQUIRED _HRESULT_TYPEDEF_(0x8009033E)
#define SEC_E_SHUTDOWN_IN_PROGRESS _HRESULT_TYPEDEF_(0x8009033F)
#define SEC_E_KDC_INVALID_REQUEST _HRESULT_TYPEDEF_(0x80090340)
#define SEC_E_KDC_UNABLE_TO_REFER _HRESULT_TYPEDEF_(0x80090341)
#define SEC_E_KDC_UNKNOWN_ETYPE _HRESULT_TYPEDEF_(0x80090342)
#define SEC_E_UNSUPPORTED_PREAUTH _HRESULT_TYPEDEF_(0x80090343)
#define SEC_E_DELEGATION_REQUIRED _HRESULT_TYPEDEF_(0x80090345)
#define SEC_E_BAD_BINDINGS _HRESULT_TYPEDEF_(0x80090346)
#define SEC_E_MULTIPLE_ACCOUNTS _HRESULT_TYPEDEF_(0x80090347)
#define SEC_E_NO_KERB_KEY _HRESULT_TYPEDEF_(0x80090348)
#define SEC_E_CERT_WRONG_USAGE _HRESULT_TYPEDEF_(0x80090349)
#define SEC_E_DOWNGRADE_DETECTED _HRESULT_TYPEDEF_(0x80090350)
#define SEC_E_SMARTCARD_CERT_REVOKED _HRESULT_TYPEDEF_(0x80090351)
#define SEC_E_ISSUING_CA_UNTRUSTED _HRESULT_TYPEDEF_(0x80090352)
#define SEC_E_REVOCATION_OFFLINE_C _HRESULT_TYPEDEF_(0x80090353)
#define SEC_E_PKINIT_CLIENT_FAILURE _HRESULT_TYPEDEF_(0x80090354)
#define SEC_E_SMARTCARD_CERT_EXPIRED _HRESULT_TYPEDEF_(0x80090355)
#define SEC_E_NO_S4U_PROT_SUPPORT _HRESULT_TYPEDEF_(0x80090356)
#define SEC_E_CROSSREALM_DELEGATION_FAILURE _HRESULT_TYPEDEF_(0x80090357)
#define SEC_E_REVOCATION_OFFLINE_KDC _HRESULT_TYPEDEF_(0x80090358)
#define SEC_E_ISSUING_CA_UNTRUSTED_KDC _HRESULT_TYPEDEF_(0x80090359)
#define SEC_E_KDC_CERT_EXPIRED _HRESULT_TYPEDEF_(0x8009035A)
#define SEC_E_KDC_CERT_REVOKED _HRESULT_TYPEDEF_(0x8009035B)
#define SEC_I_SIGNATURE_NEEDED _HRESULT_TYPEDEF_(0x0009035C)
#define SEC_E_INVALID_PARAMETER _HRESULT_TYPEDEF_(0x8009035D)
#define SEC_E_DELEGATION_POLICY _HRESULT_TYPEDEF_(0x8009035E)
#define SEC_E_POLICY_NLTM_ONLY _HRESULT_TYPEDEF_(0x8009035F)
#define SEC_I_NO_RENEGOTIATION _HRESULT_TYPEDEF_(0x00090360)
#define SEC_E_NO_CONTEXT _HRESULT_TYPEDEF_(0x80090361)
#define SEC_E_PKU2U_CERT_FAILURE _HRESULT_TYPEDEF_(0x80090362)
#define SEC_E_MUTUAL_AUTH_FAILED _HRESULT_TYPEDEF_(0x80090363)
#define SEC_I_MESSAGE_FRAGMENT _HRESULT_TYPEDEF_(0x00090364)
#define SEC_E_ONLY_HTTPS_ALLOWED _HRESULT_TYPEDEF_(0x80090365)
#define SEC_I_CONTINUE_NEEDED_MESSAGE_OK _HRESULT_TYPEDEF_(0x00090366)
#define SEC_E_APPLICATION_PROTOCOL_MISMATCH _HRESULT_TYPEDEF_(0x80090367)
#define SEC_I_ASYNC_CALL_PENDING _HRESULT_TYPEDEF_(0x00090368)
#define SEC_E_INVALID_UPN_NAME _HRESULT_TYPEDEF_(0x80090369)
#define SEC_E_EXT_BUFFER_TOO_SMALL _HRESULT_TYPEDEF_(0x8009036A)
#define SEC_E_INSUFFICIENT_BUFFERS _HRESULT_TYPEDEF_(0x8009036B)
#define SEC_E_NO_SPM SEC_E_INTERNAL_ERROR

#define SECURITY_NATIVE_DREP 0x00000010
#define SECURITY_NETWORK_DREP 0x00000000

#define SECPKG_CRED_INBOUND 0x00000001
#define SECPKG_CRED_OUTBOUND 0x00000002
#define SECPKG_CRED_BOTH 0x00000003
#define SECPKG_CRED_DEFAULT 0x00000004
#define SECPKG_CRED_RESERVED 0xF0000000

#define ISC_REQ_DELEGATE 0x00000001
#define ISC_REQ_MUTUAL_AUTH 0x00000002
#define ISC_REQ_REPLAY_DETECT 0x00000004
#define ISC_REQ_SEQUENCE_DETECT 0x00000008
#define ISC_REQ_CONFIDENTIALITY 0x00000010
#define ISC_REQ_USE_SESSION_KEY 0x00000020
#define ISC_REQ_PROMPT_FOR_CREDS 0x00000040
#define ISC_REQ_USE_SUPPLIED_CREDS 0x00000080
#define ISC_REQ_ALLOCATE_MEMORY 0x00000100
#define ISC_REQ_USE_DCE_STYLE 0x00000200
#define ISC_REQ_DATAGRAM 0x00000400
#define ISC_REQ_CONNECTION 0x00000800
#define ISC_REQ_CALL_LEVEL 0x00001000
#define ISC_REQ_FRAGMENT_SUPPLIED 0x00002000
#define ISC_REQ_EXTENDED_ERROR 0x00004000
#define ISC_REQ_STREAM 0x00008000
#define ISC_REQ_INTEGRITY 0x00010000
#define ISC_REQ_IDENTIFY 0x00020000
#define ISC_REQ_NULL_SESSION 0x00040000
#define ISC_REQ_MANUAL_CRED_VALIDATION 0x00080000
#define ISC_REQ_RESERVED1 0x00100000
#define ISC_REQ_FRAGMENT_TO_FIT 0x00200000
#define ISC_REQ_FORWARD_CREDENTIALS 0x00400000
#define ISC_REQ_NO_INTEGRITY 0x00800000
#define ISC_REQ_USE_HTTP_STYLE 0x01000000
#define ISC_REQ_UNVERIFIED_TARGET_NAME 0x20000000
#define ISC_REQ_CONFIDENTIALITY_ONLY 0x40000000
#define ISC_REQ_MESSAGES 0x0000000100000000
#define ISC_REQ_DEFERRED_CRED_VALIDATION 0x0000000200000000
#define ISC_REQ_NO_POST_HANDSHAKE_AUTH 0x0000000400000000

#define ISC_RET_DELEGATE 0x00000001
#define ISC_RET_MUTUAL_AUTH 0x00000002
#define ISC_RET_REPLAY_DETECT 0x00000004
#define ISC_RET_SEQUENCE_DETECT 0x00000008
#define ISC_RET_CONFIDENTIALITY 0x00000010
#define ISC_RET_USE_SESSION_KEY 0x00000020
#define ISC_RET_USED_COLLECTED_CREDS 0x00000040
#define ISC_RET_USED_SUPPLIED_CREDS 0x00000080
#define ISC_RET_ALLOCATED_MEMORY 0x00000100
#define ISC_RET_USED_DCE_STYLE 0x00000200
#define ISC_RET_DATAGRAM 0x00000400
#define ISC_RET_CONNECTION 0x00000800
#define ISC_RET_INTERMEDIATE_RETURN 0x00001000
#define ISC_RET_CALL_LEVEL 0x00002000
#define ISC_RET_EXTENDED_ERROR 0x00004000
#define ISC_RET_STREAM 0x00008000
#define ISC_RET_INTEGRITY 0x00010000
#define ISC_RET_IDENTIFY 0x00020000
#define ISC_RET_NULL_SESSION 0x00040000
#define ISC_RET_MANUAL_CRED_VALIDATION 0x00080000
#define ISC_RET_RESERVED1 0x00100000
#define ISC_RET_FRAGMENT_ONLY 0x00200000
#define ISC_RET_FORWARD_CREDENTIALS 0x00400000
#define ISC_RET_USED_HTTP_STYLE 0x01000000
#define ISC_RET_NO_ADDITIONAL_TOKEN 0x02000000
#define ISC_RET_REAUTHENTICATION 0x08000000
#define ISC_RET_CONFIDENTIALITY_ONLY 0x40000000
#define ISC_RET_MESSAGES 0x0000000100000000
#define ISC_RET_DEFERRED_CRED_VALIDATION 0x0000000200000000
#define ISC_RET_NO_POST_HANDSHAKE_AUTH 0x0000000400000000

#define SECBUFFER_VERSION 0
#define SECBUFFER_EMPTY 0
#define SECBUFFER_DATA 1
#define SECBUFFER_TOKEN 2
#define SECBUFFER_PKG_PARAMS 3
#define SECBUFFER_MISSING 4
#define SECBUFFER_EXTRA 5
#define SECBUFFER_STREAM_TRAILER 6
#define SECBUFFER_STREAM_HEADER 7
#define SECBUFFER_NEGOTIATION_INFO 8
#define SECBUFFER_PADDING 9
#define SECBUFFER_STREAM 10
#define SECBUFFER_MECHLIST 11
#define SECBUFFER_MECHLIST_SIGNATURE 12
#define SECBUFFER_TARGET 13
#define SECBUFFER_CHANNEL_BINDINGS 14
#define SECBUFFER_CHANGE_PASS_RESPONSE 15
#define SECBUFFER_TARGET_HOST 16
#define SECBUFFER_ALERT 17
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#define SECBUFFER_SRTP_PROTECTION_PROFILES 19
#define SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER 20
#define SECBUFFER_TOKEN_BINDING 21
#define SECBUFFER_PRESHARED_KEY 22
#define SECBUFFER_PRESHARED_KEY_IDENTITY 23
#define SECBUFFER_DTLS_MTU 24
#define SECBUFFER_SEND_GENERIC_TLS_EXTENSION 25
#define SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION 26
#define SECBUFFER_FLAGS 27
#define SECBUFFER_TRAFFIC_SECRETS 28
#define SECBUFFER_CERTIFICATE_REQUEST_CONTEXT 29

#define ASC_REQ_DELEGATE 0x00000001
#define ASC_REQ_MUTUAL_AUTH 0x00000002
#define ASC_REQ_REPLAY_DETECT 0x00000004
#define ASC_REQ_SEQUENCE_DETECT 0x00000008
#define ASC_REQ_CONFIDENTIALITY 0x00000010
#define ASC_REQ_USE_SESSION_KEY 0x00000020
#define ASC_REQ_SESSION_TICKET 0x00000040
#define ASC_REQ_ALLOCATE_MEMORY 0x00000100
#define ASC_REQ_USE_DCE_STYLE 0x00000200
#define ASC_REQ_DATAGRAM 0x00000400
#define ASC_REQ_CONNECTION 0x00000800
#define ASC_REQ_CALL_LEVEL 0x00001000
#define ASC_REQ_FRAGMENT_SUPPLIED 0x00002000
#define ASC_REQ_EXTENDED_ERROR 0x00008000
#define ASC_REQ_STREAM 0x00010000
#define ASC_REQ_INTEGRITY 0x00020000
#define ASC_REQ_LICENSING 0x00040000
#define ASC_REQ_IDENTIFY 0x00080000
#define ASC_REQ_ALLOW_NULL_SESSION 0x00100000
#define ASC_REQ_ALLOW_NON_USER_LOGONS 0x00200000
#define ASC_REQ_ALLOW_CONTEXT_REPLAY 0x00400000
#define ASC_REQ_FRAGMENT_TO_FIT 0x00800000
#define ASC_REQ_NO_TOKEN 0x01000000
#define ASC_REQ_PROXY_BINDINGS 0x04000000
#define ASC_REQ_ALLOW_MISSING_BINDINGS 0x10000000
#define ASC_REQ_MESSAGES 0x0000000100000000

DECLSPEC_IMPORT SECURITY_STATUS SECUR32$AcquireCredentialsHandleW(
	IN OPTIONAL PWSTR       pszPrincipal,
	IN PWSTR                pszPackage,
	IN ULONG                fCredentialUse,
	IN OPTIONAL PVOID       pvLogonId,
	IN OPTIONAL PVOID       pAuthData,
	IN OPTIONAL PVOID       pGetKeyFn,
	IN OPTIONAL PVOID       pvGetKeyArgument,
	OUT PCredHandle         phCredential,
	OUT OPTIONAL PTimeStamp ptsExpiry
);

DECLSPEC_IMPORT SECURITY_STATUS SECUR32$InitializeSecurityContextW(
	IN OPTIONAL PCredHandle        phCredential,
	IN OPTIONAL PCtxtHandle        phContext,
	IN OPTIONAL PWSTR              pTargetName,
	IN ULONG                       fContextReq,
	IN ULONG                       Reserved1,
	IN ULONG                       TargetDataRep,
	IN OPTIONAL PSecBufferDesc     pInput,
	IN ULONG                       Reserved2,
	IN OUT OPTIONAL PCtxtHandle    phNewContext,
	IN OUT OPTIONAL PSecBufferDesc pOutput,
	OUT PULONG                     pfContextAttr,
	OUT OPTIONAL PTimeStamp        ptsExpiry
);

DECLSPEC_IMPORT SECURITY_STATUS SECUR32$AcceptSecurityContext(
	IN OPTIONAL PCredHandle        phCredential,
	IN OPTIONAL PCtxtHandle        phContext,
	IN OPTIONAL PSecBufferDesc     pInput,
	IN ULONG                       fContextReq,
	IN ULONG                       TargetDataRep,
	IN OUT OPTIONAL PCtxtHandle    phNewContext,
	IN OUT OPTIONAL PSecBufferDesc pOutput,
	OUT ULONG *                    pfContextAttr,
	OUT OPTIONAL PTimeStamp        ptsExpiry
);

DECLSPEC_IMPORT SECURITY_STATUS SECUR32$QuerySecurityContextToken(
	PCtxtHandle phContext,
	PHANDLE     Token
);

DECLSPEC_IMPORT SECURITY_STATUS SECUR32$FreeContextBuffer(
	PVOID pvContextBuffer
);

#endif //NTLM_H
