#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>
#include <Native.h>
#include <Defs.h>

// SAM STRUCTURES
typedef PVOID SAM_HANDLE, * PSAM_HANDLE;
typedef void              * SAMPR_HANDLE;
typedef ULONG SAM_ENUMERATE_HANDLE, * PSAM_ENUMERATE_HANDLE;

typedef struct _SAMPR_RID_ENUMERATION {
	ULONG          RelativeId;
	UNICODE_STRING Name;
}                                   SAMPR_RID_ENUMERATION, * PSAMPR_RID_ENUMERATION;

typedef struct _GROUP_MEMBERSHIP {
	ULONG RelativeId;
	ULONG Attributes;
}                                                          GROUP_MEMBERSHIP, * PGROUP_MEMBERSHIP;

enum SAM_OBJECT {
	SAMMY_USER,
	SAMMY_GROUP
};

typedef struct _USER_CONTROL_INFORMATION {
	ULONG UserAccountControl;
}                                                                            USER_CONTROL_INFORMATION, * PUSER_CONTROL_INFORMATION;

// SAM CONSTANTS

// SAM Server
#define SAM_SERVER_CONNECT 1
#define SAM_SERVER_SHUTDOWN 2
#define SAM_SERVER_INITIALIZE 4
#define SAM_SERVER_CREATE_DOMAIN 8
#define SAM_SERVER_ENUMERATE_DOMAINS 16
#define SAM_SERVER_LOOKUP_DOMAIN 32
#define GENERIC_WRITE 1073741824
#define GENERIC_EXECUTE 536870912
#define DELETE 65536
#define READ_CONTROL 131072
#define WRITE_DAC 262144
#define WRITE_OWNER 524288
#define MAXIMUM_ALLOWED 33554432
#define ACCESS_SYSTEM_SECURITY 16777216
#define POLICY_LOOKUP_NAMES 2048

// SAM Domain
#define DOMAIN_READ_PASSWORD_PARAMETERS 1
#define DOMAIN_WRITE_PASSWORD_PARAMS 2
#define DOMAIN_READ_OTHER_PARAMETERS 4
#define DOMAIN_WRITE_OTHER_PARAMETERS 8
#define DOMAIN_CREATE_USER 16
#define DOMAIN_CREATE_GROUP 32
#define DOMAIN_CREATE_ALIAS 64
#define DOMAIN_GET_ALIAS_MEMBERSHIP 128
#define DOMAIN_LIST_ACCOUNTS 256
#define DOMAIN_LOOKUP 512
#define DOMAIN_ADMINISTER_SERVER 1024

// SAM User
#define USER_READ_GENERAL 1
#define USER_READ_PREFERENCES 2
#define USER_WRITE_PREFERENCES 4
#define USER_READ_LOGON 8
#define USER_READ_ACCOUNT 16
#define USER_WRITE_ACCOUNT 32
#define USER_CHANGE_PASSWORD 64
#define USER_FORCE_PASSWORD_CHANGE 128
#define USER_LIST_GROUPS 256
#define USER_READ_GROUP_INFORMATION 512
#define USER_WRITE_GROUP_INFORMATION 1024

// SAM Alias
#define ALIAS_ADD_MEMBER 1
#define ALIAS_REMOVE_MEMBER 2
#define ALIAS_LIST_MEMBERS 4
#define ALIAS_READ_INFORMATION 8
#define ALIAS_WRITE_ACCOUNT 16

// UAC struct
#define USER_ACCOUNT_DISABLED 0x00000001
#define USER_HOME_DIRECTORY_REQUIRED 0x00000002
#define USER_PASSWORD_NOT_REQUIRED 0x00000004
#define USER_TEMP_DUPLICATE_ACCOUNT 0x00000008
#define USER_NORMAL_ACCOUNT 0x00000010
#define USER_MNS_LOGON_ACCOUNT 0x00000020
#define USER_INTERDOMAIN_TRUST_ACCOUNT 0x00000040
#define USER_WORKSTATION_TRUST_ACCOUNT 0x00000080
#define USER_SERVER_TRUST_ACCOUNT 0x00000100
#define USER_DONT_EXPIRE_PASSWORD 0x00000200
#define USER_ACCOUNT_AUTO_LOCKED 0x00000400
#define USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED 0x00000800
#define USER_SMARTCARD_REQUIRED 0x00001000
#define USER_TRUSTED_FOR_DELEGATION 0x00002000
#define USER_NOT_DELEGATED 0x00004000
#define USER_USE_DES_KEY_ONLY 0x00008000
#define USER_DONT_REQUIRE_PREAUTH 0x00010000
#define USER_PASSWORD_EXPIRED 0x00020000
#define USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION 0x00040000
#define USER_NO_AUTH_DATA_REQUIRED 0x00080000
#define USER_PARTIAL_SECRETS_ACCOUNT 0x00100000
#define USER_USE_AES_KEYS 0x00200000

typedef enum _USER_INFORMATION_CLASS {
	UserGeneralInformation = 1,
	UserPreferencesInformation,
	UserLogonInformation,
	UserLogonHoursInformation,
	UserAccountInformation,
	UserNameInformation,
	UserAccountNameInformation,
	UserFullNameInformation,
	UserPrimaryGroupInformation,
	UserHomeInformation,
	UserScriptInformation,
	UserProfileInformation,
	UserAdminCommentInformation,
	UserWorkStationsInformation,
	UserSetPasswordInformation,
	UserControlInformation,
	UserExpiresInformation,
	UserInternal1Information,
	UserInternal2Information,
	UserParametersInformation,
	UserAllInformation,
	UserInternal3Information,
	UserInternal4Information,
	UserInternal5Information,
	UserInternal4InformationNew,
	UserInternal5InformationNew,
	UserInternal6Information,
	UserExtendedInformation,
	UserLogonUIInformation,
}                                                                                                      USER_INFORMATION_CLASS, * PUSER_INFORMATION_CLASS;
#define USER_ALL_USERNAME 0x00000001
#define USER_ALL_FULLNAME 0x00000002
#define USER_ALL_USERID 0x00000004
#define USER_ALL_PRIMARYGROUPID 0x00000008
#define USER_ALL_ADMINCOMMENT 0x00000010
#define USER_ALL_USERCOMMENT 0x00000020
#define USER_ALL_HOMEDIRECTORY 0x00000040
#define USER_ALL_HOMEDIRECTORYDRIVE 0x00000080
#define USER_ALL_SCRIPTPATH 0x00000100
#define USER_ALL_PROFILEPATH 0x00000200
#define USER_ALL_WORKSTATIONS 0x00000400
#define USER_ALL_LASTLOGON 0x00000800
#define USER_ALL_LASTLOGOFF 0x00001000
#define USER_ALL_LOGONHOURS 0x00002000
#define USER_ALL_BADPASSWORDCOUNT 0x00004000
#define USER_ALL_LOGONCOUNT 0x00008000
#define USER_ALL_PASSWORDCANCHANGE 0x00010000
#define USER_ALL_PASSWORDMUSTCHANGE 0x00020000
#define USER_ALL_PASSWORDLASTSET 0x00040000
#define USER_ALL_ACCOUNTEXPIRES 0x00080000
#define USER_ALL_USERACCOUNTCONTROL 0x00100000
#define USER_ALL_PARAMETERS 0x00200000
#define USER_ALL_COUNTRYCODE 0x00400000
#define USER_ALL_CODEPAGE 0x00800000
#define USER_ALL_NTPASSWORDPRESENT 0x01000000
#define USER_ALL_LMPASSWORDPRESENT 0x02000000
#define USER_ALL_PRIVATEDATA 0x04000000
#define USER_ALL_PASSWORDEXPIRED 0x08000000
#define USER_ALL_SECURITYDESCRIPTOR 0x10000000
#define USER_ALL_UNDEFINED_MASK 0xC0000000

// Logon rights
#define SeInteractiveLogonRight 0
#define SeNetworkLogonRight 1
#define SeBatchLogonRight 2
#define SeServiceLogonRight 3
#define SeRemoteInteractiveLogonRight 4
#define SeDenyInteractiveLogonRight 5
#define SeDenyNetworkLogonRight 6
#define SeDenyBatchLogonRight 7
#define SeDenyServiceLogonRight 8
#define SeDenyRemoteInteractiveLogonRight 9

// access mask LsaOpenPolicy
#define POLICY_VIEW_LOCAL_INFORMATION 1
#define POLICY_VIEW_AUDIT_INFORMATION 2
#define POLICY_GET_PRIVATE_INFORMATION 4
#define POLICY_TRUST_ADMIN 8
#define POLICY_CREATE_ACCOUNT 16
#define POLICY_CREATE_SECRET 32
#define POLICY_CREATE_PRIVILEGE 64
#define POLICY_SET_DEFAULT_QUOTA_LIMITS 128
#define POLICY_SET_AUDIT_REQUIREMENTS 256
#define POLICY_AUDIT_LOG_ADMIN 512
#define POLICY_SERVER_ADMIN 1024
#define POLICY_LOOKUP_NAMES 2048
#define POLICY_NOTIFICATION 4096

typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG  HighPart;
}                                                                                                                              OLD_LARGE_INTEGER, * POLD_LARGE_INTEGER;

typedef struct _RPC_SHORT_BLOB {
	USHORT  Length;
	USHORT  MaximumLength;
	PUSHORT Buffer;
}                                                                                                                                                 RPC_SHORT_BLOB, * PRPC_SHORT_BLOB;

typedef struct _SAMPR_SR_SECURITY_DESCRIPTOR {
	ULONG Length;
	PBYTE SecurityDescriptor;
}                                                                                                                                                                 SAMPR_SR_SECURITY_DESCRIPTOR, * PSAMPR_SR_SECURITY_DESCRIPTOR;

typedef struct _SAMPR_LOGON_HOURS {
	USHORT UnitsPerWeek;
	PCHAR  LogonHours;
}                                                                                                                                                                                               SAMPR_LOGON_HOURS, * PSAMPR_LOGON_HOURS;

typedef struct _USER_SET_PASSWORD_INFORMATION {
	UNICODE_STRING Password;
	BOOLEAN        PasswordExpired;
}                                                                                                                                                                                                                  USER_SET_PASSWORD_INFORMATION, * PUSER_SET_PASSWORD_INFORMATION;

typedef struct _SAMPR_USER_ALL_INFORMATION {
	OLD_LARGE_INTEGER            LastLogon;
	OLD_LARGE_INTEGER            LastLogoff;
	OLD_LARGE_INTEGER            PasswordLastSet;
	OLD_LARGE_INTEGER            AccountExpires;
	OLD_LARGE_INTEGER            PasswordCanChange;
	OLD_LARGE_INTEGER            PasswordMustChange;
	UNICODE_STRING               UserName;
	UNICODE_STRING               FullName;
	UNICODE_STRING               HomeDirectory;
	UNICODE_STRING               HomeDirectoryDrive;
	UNICODE_STRING               ScriptPath;
	UNICODE_STRING               ProfilePath;
	UNICODE_STRING               AdminComment;
	UNICODE_STRING               WorkStations;
	UNICODE_STRING               UserComment;
	UNICODE_STRING               Parameters;
	RPC_SHORT_BLOB               LmOwfPassword;
	RPC_SHORT_BLOB               NtOwfPassword;
	UNICODE_STRING               PrivateData;
	SAMPR_SR_SECURITY_DESCRIPTOR SecurityDescriptor;
	ULONG                        UserId;
	ULONG                        PrimaryGroupId;
	ULONG                        UserAccountControl;
	ULONG                        WhichFields;
	SAMPR_LOGON_HOURS            LogonHours;
	USHORT                       BadPasswordCount;
	USHORT                       LogonCount;
	USHORT                       CountryCode;
	USHORT                       CodePage;
	BYTE                         LmPasswordPresent;
	BYTE                         NtPasswordPresent;
	BYTE                         PasswordExpired;
	BYTE                         PrivateDataSensitive;
}                                                                                                                                                                                                                                                 SAMPR_USER_ALL_INFORMATION, * PSAMPR_USER_ALL_INFORMATION;

typedef enum _DOMAIN_INFORMATION_CLASS {
	DomainPasswordInformation    = 1,
	DomainGeneralInformation     = 2,
	DomainLogoffInformation      = 3,
	DomainOemInformation         = 4,
	DomainNameInformation        = 5,
	DomainReplicationInformation = 6,
	DomainServerRoleInformation  = 7,
	DomainModifiedInformation    = 8,
	DomainStateInformation       = 9,
	DomainGeneralInformation2    = 11,
	DomainLockoutInformation     = 12,
	DomainModifiedInformation2   = 13
}                                                                                                                                                                                                                                                                             DOMAIN_INFORMATION_CLASS;

#define DOMAIN_PASSWORD_COMPLEX 0x01
#define DOMAIN_PASSWORD_NO_CLEAR_CHANGE 0x04
#define DOMAIN_PASSWORD_STORE_CLEARTEXT 0x10

typedef struct _SAMPR_ENCRYPTED_USER_PASSWORD {
	BYTE Buffer[( 256 * 2 ) + 4];
}                                                                                                                                                                                                                                                                             SAMPR_ENCRYPTED_USER_PASSWORD, * PSAMPR_ENCRYPTED_USER_PASSWORD;

typedef struct _SAMPR_USER_PASSWORD {
	USHORT Buffer[256];
	ULONG  Length;
}                                                                                                                                                                                                                                                                                                            SAMPR_USER_PASSWORD, * PSAMPR_USER_PASSWORD;

typedef struct _DOMAIN_PASSWORD_INFORMATION {
	USHORT            MinPasswordLength;
	USHORT            PasswordHistoryLength;
	ULONG             PasswordProperties;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
}                                                                                                                                                                                                                                                                                                                                 DOMAIN_PASSWORD_INFORMATION, * PDOMAIN_PASSWORD_INFORMATION;

typedef struct _SAMPR_DOMAIN_LOCKOUT_INFORMATION {
	LARGE_INTEGER LockoutDuration;
	LARGE_INTEGER LockoutObservationWindow;
	USHORT        LockoutThreshold;
}                                                                                                                                                                                                                                                                                                                                                              SAMPR_DOMAIN_LOCKOUT_INFORMATION, * PSAMPR_DOMAIN_LOCKOUT_INFORMATION;

typedef struct _SID_CUSTOM {
	BYTE                     Revision;
	BYTE                     SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	DWORD                    SubAuthority[11]; // not PDWORD (can't replace it), c++ template would have been cool :(
}                                                                                                                                                                                                                                                                                                                                                                                                SID_CUSTOM, * PSID_CUSTOM;

// SAM FUNCTIONS
DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamQueryInformationDomain(
	IN SAM_HANDLE DomainHandle,
	IN DOMAIN_INFORMATION_CLASS DomainInformationClass,
	OUT PVOID * Buffer
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamAddMemberToAlias(
	IN SAM_HANDLE AliasHandle,
	IN PSID MemberId
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamRemoveMemberFromAlias(
	IN SAM_HANDLE AliasHandle,
	IN PSID MemberId
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamDeleteAlias(
	IN SAM_HANDLE AliasHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamCreateAliasInDomain(
	IN SAM_HANDLE DomainHandle,
	IN PUNICODE_STRING AccountName,
	IN ACCESS_MASK DesiredAccess,
	OUT PSAM_HANDLE AliasHandle,
	OUT PULONG RelativeId
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamConnect(
	IN OUT PUNICODE_STRING ServerName OPTIONAL,
	OUT PSAM_HANDLE ServerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamOpenDomain(
	IN SAM_HANDLE ServerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PSID DomainId,
	OUT PSAM_HANDLE DomainHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamLookupDomainInSamServer(
	IN SAM_HANDLE ServerHandle,
	IN PUNICODE_STRING Name,
	OUT PSID * DomainId
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamEnumerateDomainsInSamServer(
	IN SAM_HANDLE ServerHandle,
	IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext,
	OUT PVOID * Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamEnumerateUsersInDomain(
	IN SAM_HANDLE DomainHandle,
	IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext,
	IN ULONG UserAccountControl,
	OUT PVOID * Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamEnumerateAliasesInDomain(
	IN SAM_HANDLE DomainHandle,
	IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext,
	OUT PVOID * Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamOpenDomain(
	IN SAM_HANDLE ServerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN PSID DomainId,
	OUT PSAM_HANDLE DomainHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamLookupNamesInDomain(
	IN SAM_HANDLE DomainHandle,
	IN ULONG Count,
	IN PUNICODE_STRING Names,
	OUT PULONG * RelativeIds,
	OUT PSID_NAME_USE * Use
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamOpenUser(
	IN SAM_HANDLE DomainHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG UserId,
	OUT PSAM_HANDLE UserHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamOpenAlias(
	IN SAM_HANDLE DomainHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG AliasId,
	OUT PSAM_HANDLE AliasHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamGetMembersInAlias(
	IN SAM_HANDLE AliasHandle,
	OUT PSID ** MemberIds,
	OUT PULONG MemberCount
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamCreateUser2InDomain(
	IN SAM_HANDLE DomainHandle,
	IN PUNICODE_STRING AccountName,
	IN ULONG AccountType,
	IN ACCESS_MASK DesiredAccess,
	OUT PSAM_HANDLE UserHandle,
	OUT PULONG GrantedAccess,
	OUT PULONG RelativeId
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamDeleteUser(
	IN SAM_HANDLE UserHandle
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamSetInformationUser(
	IN SAM_HANDLE UserHandle,
	IN USER_INFORMATION_CLASS UserInformationClass,
	IN PVOID Buffer
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamChangePasswordUser(
	IN SAM_HANDLE UserHandle,
	IN PUNICODE_STRING OldPassword,
	IN PUNICODE_STRING NewPassword
);

DECLSPEC_IMPORT NTSTATUS NTAPI SAMLIB$SamFreeMemory(
	IN PVOID Buffer
);

// NTDLL functions
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlConvertSidToUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString,
	_In_ PSID Sid,
	_In_ BOOLEAN AllocateDestinationString
);

DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlFreeUnicodeString(
	PUNICODE_STRING UnicodeString
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(
	HANDLE Handle
);

DECLSPEC_IMPORT VOID NTAPI NTDLL$RtlFreeUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString
);

// ADVAPI32
DECLSPEC_IMPORT BOOL ADVAPI32$ConvertStringSidToSidA(
	LPCSTR StringSid,
	PSID * Sid
);

DECLSPEC_IMPORT NTSTATUS ADVAPI32$LsaEnumerateAccountRights(
	LSA_HANDLE PolicyHandle,
	PSID AccountSid,
	PUNICODE_STRING * UserRights,
	PULONG CountOfRights
);

DECLSPEC_IMPORT NTSTATUS ADVAPI32$LsaOpenPolicy(
	PUNICODE_STRING SystemName,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ACCESS_MASK DesiredAccess,
	PLSA_HANDLE PolicyHandle
);

DECLSPEC_IMPORT NTSTATUS ADVAPI32$LsaLookupNames2(
	LSA_HANDLE PolicyHandle,
	ULONG Flags,
	ULONG Count,
	PUNICODE_STRING Names,
	PLSA_REFERENCED_DOMAIN_LIST * ReferencedDomains,
	PLSA_TRANSLATED_SID2 * Sids
);

DECLSPEC_IMPORT NTSTATUS ADVAPI32$LsaLookupSids2(
	LSA_HANDLE PolicyHandle,
	ULONG LookupOptions,
	ULONG Count,
	PSID * Sids,
	PLSA_REFERENCED_DOMAIN_LIST * ReferencedDomains,
	PLSA_TRANSLATED_NAME * Names
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaAddAccountRights(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN PUNICODE_STRING UserRights,
	IN ULONG CountOfRights
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaCreateAccount(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN ACCESS_MASK DesiredAccess,
	OUT PLSA_HANDLE AccountHandle
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaRemoveAccountRights(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN BOOLEAN AllRights,
	IN PUNICODE_STRING UserRights,
	IN ULONG CountOfRights
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaAddPrivilegesToAccount(
	IN LSA_HANDLE AccountHandle,
	IN PPRIVILEGE_SET PrivilegeSet
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaOpenAccount(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN ACCESS_MASK DesiredAccess,
	OUT PLSA_HANDLE AccountHandle
);

DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaRemovePrivilegesFromAccount(
	IN LSA_HANDLE AccountHandle,
	IN BOOLEAN AllPrivileges,
	IN PPRIVILEGE_SET Privileges    OPTIONAL
);

DECLSPEC_IMPORT NTSTATUS ADVAPI32$LsaFreeMemory(
	PVOID Buffer
);

// KERNEL32
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(
	HLOCAL hMem
);

#endif //SAMMY_H
