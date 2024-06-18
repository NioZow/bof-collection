#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>
#include <Native.h>

// windows internals private structures non-declared in Native.h
#define HEAP_CREATE_SEGMENT_HEAP 0x100

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE {
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE {
	PVOID pValue;
	ULONG ValueLength;
}                                      TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1 {
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union {
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	}              Values;
}                                                                                   TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union {
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	}      Attribute;
}                                                                                                                TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _TOKEN_GROUPS_MULTI {
	DWORD               GroupCount;
	PSID_AND_ATTRIBUTES Groups;
}                                                                                                                                                       TOKEN_GROUPS_MULTI, * PTOKEN_GROUPS_MULTI;

typedef struct _TOKEN_PRIVILEGES_MULTI {
	DWORD                PrivilegeCount;
	PLUID_AND_ATTRIBUTES Privileges;
}                                                                                                                                                                           TOKEN_PRIVILEGES_MULTI, * PTOKEN_PRIVILEGES_MULTI;

#endif //INTERNALS_H
