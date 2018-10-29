/* p11-multiplex.cpp
 
   Copyright 2006 Shahin Hajikhorasani

   This file is a part of Cryptokis' Multiplexer project.
   The project short name is cryptokimpx.
   
   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.
   
   Please submit changes back to the original project at github or send
   an email to shahin.khorasani@gmail.com
*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include "INIReader.h"
using std::cout;
using std::endl;

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <limits.h>

#include <Psapi.h>
#include <Aclapi.h> 
#else
#include <unistd.h>
#endif

#define CRYPTOKI_EXPORTS
#include "p11-helper.h"
#include  <stdio.h>
#include  <stdlib.h>

bool g_bEnableLog		= true;
bool g_bEnableMultiLog		= false;

const char *g_strCryprokiSection	= "Cryptoki";
const char *g_strLogSection		= "LOG";
const char *g_strCryprokiPrefix		= "FILE_PATH_";

char *g_strCryptokiConf	= {0};
bool g_bIsStaticConf	= false;

static CK_FUNCTION_LIST_PTR p11_multiplex = NULL;
static CK_FUNCTION_LIST_PTR *pos = NULL;
static void **modhandles = NULL;
static FILE *p11mpx_output = NULL;

#ifdef _WIN32
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
CRITICAL_SECTION CriticalSection;
CRITICAL_SECTION SessionCriticalSection;
CRITICAL_SECTION SlotCriticalSection;
extern bool gExt_bExitThread;
extern bool gExt_bDllDetachCalled;
int g_iWaitEventsCount = 0;
#else
bool gExt_bExitThread = false;
bool gExt_bDllDetachCalled = false;
#endif

#define MULTIPLEXER_MANUFACTURERID		"Shahin Hajikhorasani                      "
#define MULTIPLEXER_LIBRARY_DESCRIPTION		"Cryptokis' Multiplexer                    "
#define VERSION_MAJOR				1
#define VERSION_MINOR				1
#define VERSION_MINOR_2				1
#define VERSION_MINOR_3				1
#define MAX_EVENT_ARRAY_SIZE			30
#define MAX_WAIT_FOR_CS				500 

#include <string>
#include <string.h>
#include <vector>
using namespace std;
char g_strLogFilePath[FILENAME_MAX];

#ifndef _WIN32

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

Dl_info dl_info;
void on_load(void) __attribute__((constructor));
void on_load(void) 
{
    dladdr((void *) on_load, &dl_info);
}
#endif

struct stMapCryptoki
{
	CK_ULONG			ulSlotId;
	CK_ULONG			ulRealSlotId;
	CK_FUNCTION_LIST_PTR		ulFuncPointer;
	CK_BBOOL			bIsPresent;
};

struct stMapSessions
{
	CK_ULONG			ulSlotId;
	vector<CK_SESSION_HANDLE>	vulSession;
	vector<CK_SESSION_HANDLE> 	vulFakeSession;
};

string	*g_szCryptoKiPaths	= NULL;
bool	g_bSessionAlreadyMapped = false;
bool	g_bAlreadyInited	= false;
int	g_nCryptoKiCount	= 0;

vector<struct stMapCryptoki>	g_vCryptoMaps;
vector<struct stMapSessions>	g_vSessionMaps;
vector<string> g_vLastCryptoKiPaths;
vector<string> g_vChangedCryptoKiPaths;

bool g_bAnyThreadError = false;
bool g_bIsThereAnyChangesInModuless = false;

struct Thread_Args
{
	int index;
	CK_FLAGS taskflags;
	CK_SLOT_ID taskpSlot;
	CK_VOID_PTR taskpRserved;
	int Seed;
};

struct g_CryptSlot
{
	int cryptokiNum;
	int slotNum;
};

g_CryptSlot	g_CryptSlotArray[150]	= {0};
int		g_CryptSlotArrayPtr	= 0;

CK_RV SetConfigurationStatic(char* config)
{
	if(!config)
		return CKR_GENERAL_ERROR;

	g_strCryptokiConf = (char*) malloc(strlen(config) + 1);

	if(!g_strCryptokiConf)
		return CKR_GENERAL_ERROR;

	memset(g_strCryptokiConf, 0x00, strlen(config) + 1);
	memcpy(g_strCryptokiConf, config, strlen(config));
	g_bIsStaticConf = true;

	return CKR_OK;
}

CK_RV updateSession(CK_SLOT_ID ulSlot, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hFakeSession)
{
	CK_FUNCTION_LIST_PTR   pFunc = NULL;

	bool bFound = false;
	for(unsigned int i = 0; i < g_vSessionMaps.size(); i++)
	{
		if(g_vSessionMaps[i].ulSlotId == ulSlot)
		{
			g_vSessionMaps[i].vulSession.push_back(hSession);
			g_vSessionMaps[i].vulFakeSession.push_back(hFakeSession);
			bFound = true;
		}
	}

	if(!bFound)
	{
		struct stMapSessions stSess;
		stSess.ulSlotId = ulSlot;
		stSess.vulSession.push_back(hSession);
		stSess.vulFakeSession.push_back(hFakeSession);
		g_vSessionMaps.push_back(stSess);
	}

	return CKR_OK;
}

CK_RV updateSession2(CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hNewSession)
{
	CK_FUNCTION_LIST_PTR   pFunc = NULL;

	for(size_t i = 0; i < g_vSessionMaps.size(); i++)
	{
		for(size_t j = 0; j < g_vSessionMaps[i].vulSession.size(); j++)
			if(g_vSessionMaps[i].vulSession[j] == hSession)
			{
				g_vSessionMaps[i].vulSession[j] = hNewSession;
				g_vSessionMaps[i].vulFakeSession[j] = hNewSession;
			}
	}

	return CKR_OK;
}

CK_RV updatSlotLists()
{
	CK_ULONG	ulPresentsCount = 0, ulAllCount = 0, res = 0;
	int i = 0, j = 0, k = 0; 
	CK_SLOT_ID pSlotIDs[MAX_EVENT_ARRAY_SIZE] = {0x00};
	CK_SLOT_ID pAllSlotIDs[MAX_EVENT_ARRAY_SIZE] = {0x00};
	ulPresentsCount = MAX_EVENT_ARRAY_SIZE;
	ulAllCount = MAX_EVENT_ARRAY_SIZE;
	struct stMapCryptoki	stMapCr;

	g_vCryptoMaps.clear();

	int nCounter = 0;

	for(i = 0; i < g_nCryptoKiCount; i++)
	{
		ulPresentsCount = 0;
		ulAllCount = 0;
		if(pos[i] == NULL)
			continue;

		ulPresentsCount = MAX_EVENT_ARRAY_SIZE;
		ulAllCount = MAX_EVENT_ARRAY_SIZE;
		memset(pSlotIDs, 0x00, sizeof(pSlotIDs));
		memset(pSlotIDs, 0x00, sizeof(pAllSlotIDs));
		res = pos[i]->C_GetSlotList(true, pSlotIDs, &ulPresentsCount);
		if(res)
		{
			return res;
		}

		res = pos[i]->C_GetSlotList(false, pAllSlotIDs, &ulAllCount);
		if(res)
		{
			return res;
		}

		p11_log(string_format("UpdateSlotlist: ulPresentsCount %d  \n", ulPresentsCount));

		bool bSlotPresent = false;
		for(CK_ULONG j = 0; j < ulAllCount; j++)
		{
			bSlotPresent = false;
			for(CK_ULONG k = 0; k < ulPresentsCount; k++)
			{
				if(pSlotIDs[k] == pAllSlotIDs[j])
				{
					CK_SLOT_INFO slotInfo;
					res = pos[i]->C_GetSlotInfo(pSlotIDs[k], &slotInfo);
					if (res == CKR_TOKEN_NOT_PRESENT)
						bSlotPresent = false;
					else
						bSlotPresent = true;
				}
			}

			stMapCr.bIsPresent = bSlotPresent;
			stMapCr.ulSlotId = j + nCounter;
			stMapCr.ulFuncPointer = pos[i];
			stMapCr.ulRealSlotId = pAllSlotIDs[j];
			g_vCryptoMaps.push_back(stMapCr);

			if(!g_bSessionAlreadyMapped)
			{
				g_vSessionMaps.clear();
				struct stMapSessions stTmp; 
				stTmp.ulSlotId = j + nCounter;
				stTmp.vulSession.push_back(-1);
				stTmp.vulFakeSession.push_back(-1);
				g_vSessionMaps.push_back(stTmp);
			}
		}

		nCounter += ulAllCount;
	}

	if(nCounter)
		g_bSessionAlreadyMapped = true;

	return CKR_OK;
}

CK_SLOT_ID	getRealSlotID(CK_SLOT_ID ulSLoID)
{
	CK_SLOT_ID  ulRealSlot = 0;

#ifdef _WIN32
	EnterCriticalSection(&SlotCriticalSection);
#endif

	for(unsigned int i = 0; i < g_vCryptoMaps.size(); i++)
	{
		if (g_vCryptoMaps[i].ulSlotId == ulSLoID)
		{
			ulRealSlot = g_vCryptoMaps[i].ulRealSlotId;
		}
	}

#ifdef _WIN32
	LeaveCriticalSection(&SlotCriticalSection);
#endif

	return ulRealSlot;
}

CK_SLOT_ID	getVirtualSlotID(CK_SLOT_ID ulSLoID)
{
	CK_SLOT_ID  ulRealSlot = 0;
	for(unsigned int i = 0; i < g_vCryptoMaps.size(); i++)
	{
		if(g_vCryptoMaps[i].ulRealSlotId == ulSLoID)
			ulRealSlot = g_vCryptoMaps[i].ulSlotId;
	}

	return ulRealSlot;
}

CK_FUNCTION_LIST_PTR getPOFromSlotID(CK_SLOT_ID ulSLoID)
{
	CK_FUNCTION_LIST_PTR   pFunc = NULL;

#ifdef _WIN32
	EnterCriticalSection(&SlotCriticalSection);
#endif

	for(unsigned int i = 0; i < g_vCryptoMaps.size(); i++)
	{
		if(g_vCryptoMaps[i].ulSlotId == ulSLoID)
		{
			pFunc = g_vCryptoMaps[i].ulFuncPointer;
		}
	}

#ifdef _WIN32
	LeaveCriticalSection(&SlotCriticalSection);
#endif

	return pFunc;
}

CK_RV closeAllSession(CK_SLOT_ID ulSlot)
{
	CK_FUNCTION_LIST_PTR   pFunc = NULL;
	for(unsigned int i = 0; i < g_vSessionMaps.size(); i++)
	{
		if(g_vSessionMaps[i].ulSlotId  == ulSlot)
		{
			g_vSessionMaps[i].vulSession.clear();
			g_vSessionMaps[i].vulFakeSession.clear();
		}
	}

	return CKR_OK;
}

CK_FUNCTION_LIST_PTR getPOFromSession(CK_SESSION_HANDLE *hSession)
{
	CK_FUNCTION_LIST_PTR   pFunc = NULL;
	CK_SLOT_ID ulSlotID = 0;
	bool bFound = false;

	for(size_t i = 0; i < g_vSessionMaps.size(); i++)
	{
		for(size_t j = 0; j < g_vSessionMaps[i].vulSession.size(); j++)
		{
			if(g_vSessionMaps[i].vulFakeSession[j] == *hSession)
			{
				ulSlotID = g_vSessionMaps[i].ulSlotId;
				*hSession = g_vSessionMaps[i].vulSession[j];
				bFound = true;
				break;
			}
		}

		if(bFound)
			break;
	}

	return bFound ?  getPOFromSlotID(ulSlotID) : NULL;
}

static CK_RV init_p11mpx(void)
{
	const char *output,*module;
	int rv = CKR_OK;

	char temp_path[FILENAME_MAX];

	p11_multiplex = (CK_FUNCTION_LIST_PTR) malloc(sizeof(CK_FUNCTION_LIST));
	if(p11_multiplex)
	{
		p11_multiplex->version.major = 1;
		p11_multiplex->version.major = 1;
		SetConfigurationStatic;
		p11_multiplex->C_Initialize = C_Initialize;
		p11_multiplex->C_Finalize = C_Finalize;
		p11_multiplex->C_GetInfo = C_GetInfo;
		p11_multiplex->C_GetFunctionList = C_GetFunctionList;
		p11_multiplex->C_GetSlotList = C_GetSlotList;
		p11_multiplex->C_GetSlotInfo = C_GetSlotInfo;
		p11_multiplex->C_GetTokenInfo = C_GetTokenInfo;
		p11_multiplex->C_GetMechanismList = C_GetMechanismList;
		p11_multiplex->C_GetMechanismInfo = C_GetMechanismInfo;
		p11_multiplex->C_InitToken = C_InitToken;
		p11_multiplex->C_InitPIN = C_InitPIN;
		p11_multiplex->C_SetPIN = C_SetPIN;
		p11_multiplex->C_OpenSession = C_OpenSession;
		p11_multiplex->C_CloseSession = C_CloseSession;
		p11_multiplex->C_CloseAllSessions = C_CloseAllSessions;
		p11_multiplex->C_GetSessionInfo = C_GetSessionInfo;
		p11_multiplex->C_GetOperationState = C_GetOperationState;
		p11_multiplex->C_SetOperationState = C_SetOperationState;
		p11_multiplex->C_Login = C_Login;
		p11_multiplex->C_Logout = C_Logout;
		p11_multiplex->C_CreateObject = C_CreateObject;
		p11_multiplex->C_CopyObject = C_CopyObject;
		p11_multiplex->C_DestroyObject = C_DestroyObject;
		p11_multiplex->C_GetObjectSize = C_GetObjectSize;
		p11_multiplex->C_GetAttributeValue = C_GetAttributeValue;
		p11_multiplex->C_SetAttributeValue = C_SetAttributeValue;
		p11_multiplex->C_FindObjectsInit = C_FindObjectsInit;
		p11_multiplex->C_FindObjects = C_FindObjects;
		p11_multiplex->C_FindObjectsFinal = C_FindObjectsFinal;
		p11_multiplex->C_EncryptInit = C_EncryptInit;
		p11_multiplex->C_Encrypt = C_Encrypt;
		p11_multiplex->C_EncryptUpdate = C_EncryptUpdate;
		p11_multiplex->C_EncryptFinal = C_EncryptFinal;
		p11_multiplex->C_DecryptInit = C_DecryptInit;
		p11_multiplex->C_Decrypt = C_Decrypt;
		p11_multiplex->C_DecryptUpdate = C_DecryptUpdate;
		p11_multiplex->C_DecryptFinal = C_DecryptFinal;
		p11_multiplex->C_DigestInit = C_DigestInit;
		p11_multiplex->C_Digest = C_Digest;
		p11_multiplex->C_DigestUpdate = C_DigestUpdate;
		p11_multiplex->C_DigestKey = C_DigestKey;
		p11_multiplex->C_DigestFinal = C_DigestFinal;
		p11_multiplex->C_SignInit = C_SignInit;
		p11_multiplex->C_Sign = C_Sign;
		p11_multiplex->C_SignUpdate = C_SignUpdate;
		p11_multiplex->C_SignFinal = C_SignFinal;
		p11_multiplex->C_SignRecoverInit = C_SignRecoverInit;
		p11_multiplex->C_SignRecover = C_SignRecover;
		p11_multiplex->C_VerifyInit = C_VerifyInit;
		p11_multiplex->C_Verify = C_Verify;
		p11_multiplex->C_VerifyUpdate = C_VerifyUpdate;
		p11_multiplex->C_VerifyFinal = C_VerifyFinal;
		p11_multiplex->C_VerifyRecoverInit = C_VerifyRecoverInit;
		p11_multiplex->C_VerifyRecover = C_VerifyRecover;
		p11_multiplex->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
		p11_multiplex->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
		p11_multiplex->C_SignEncryptUpdate = C_SignEncryptUpdate;
		p11_multiplex->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
		p11_multiplex->C_GenerateKey = C_GenerateKey;
		p11_multiplex->C_GenerateKeyPair = C_GenerateKeyPair;
		p11_multiplex->C_WrapKey = C_WrapKey;
		p11_multiplex->C_UnwrapKey = C_UnwrapKey;
		p11_multiplex->C_DeriveKey = C_DeriveKey;
		p11_multiplex->C_SeedRandom = C_SeedRandom;
		p11_multiplex->C_GenerateRandom = C_GenerateRandom;
		p11_multiplex->C_GetFunctionStatus = C_GetFunctionStatus;
		p11_multiplex->C_CancelFunction = C_CancelFunction;
		p11_multiplex->C_WaitForSlotEvent = C_WaitForSlotEvent;
	}
	else
	{
		return CKR_HOST_MEMORY;
	}

	string strCryptoKis = "";
	string strConfPath = "";
	char strModulePath[FILENAME_MAX] = {0};
	size_t unFound = 0; 

#ifdef _WIN32
	GetModuleFileName((HINSTANCE)&__ImageBase, strModulePath, _countof(strModulePath));
	strConfPath = string(strModulePath);
	unFound = strConfPath.find_last_of(".");
	strConfPath = strConfPath.substr(0, unFound) + string(".cfg");
#else
	strConfPath = string(dl_info.dli_fname);
	unFound = strConfPath.rfind('.');
	strConfPath = strConfPath.substr(0, unFound) + string(".cfg");
#endif
	
	int nCounter = 0;
	char buf[FILENAME_MAX * 2];

	INIReader reader;

	if(!g_bIsStaticConf)
	{
		reader.SetConfig(strConfPath, g_bIsStaticConf);
	}
	else
	{
		reader.SetConfig(g_strCryptokiConf, g_bIsStaticConf);
	}
		
	if(reader.ParseError() < 0) 
	{
		return CKR_GENERAL_ERROR;
	}

	string strBuf = "";
	char pBuf[MAX_PATH];
	GetModuleFileName(NULL, pBuf, MAX_PATH);
	string defaultPath(pBuf);
	size_t lastdot = defaultPath.find_last_of(".");
	if(lastdot != std::string::npos)
		defaultPath = defaultPath.substr(0, lastdot);

	defaultPath = defaultPath.append("_p11.log");

	g_bEnableLog = reader.GetBoolean(g_strLogSection, "ENABLE", true);
	g_bEnableMultiLog = reader.GetBoolean(g_strLogSection, "SEPARATE_FILES", false);

	if(g_bEnableLog)
	{
		strBuf = reader.Get(g_strLogSection, "FILE_PATH", defaultPath);
		strcpy(temp_path, strBuf.c_str());

		strcpy(g_strLogFilePath, strBuf.c_str());

		output = temp_path;

#ifdef _WIN32
		void *dHandle = CreateFile(output, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
				(LPSECURITY_ATTRIBUTES) NULL, OPEN_ALWAYS, 0, NULL);

		if(dHandle == INVALID_HANDLE_VALUE) // check if this path is not writable
		{
			strcpy(temp_path, defaultPath.c_str());
			output = temp_path;

			void *dHandle2 = CreateFile(output, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
					(LPSECURITY_ATTRIBUTES)NULL, OPEN_ALWAYS, 0, NULL);

			if(dHandle2 == INVALID_HANDLE_VALUE) // check for ability to write log
			{
				g_bEnableLog = false;
			}
		}
#endif
		p11mpx_output = fopen(output, "a");

#ifndef _WIN32    
		if(!p11mpx_output)
		{
			strcpy(temp_path, defaultPath.c_str());
			output = temp_path;
			p11mpx_output = fopen(output, "a");
		}
#endif

		strncpy(g_strLogFilePath, output, sizeof g_strLogFilePath);
		g_strLogFilePath[sizeof g_strLogFilePath - 1] = '\0';
	}

	SetGlobalSettings(g_bEnableLog, g_bEnableMultiLog, g_strLogFilePath);

	while(true)
	{
		sprintf(buf, "%s%d", g_strCryprokiPrefix, nCounter);
		strBuf = reader.Get(g_strCryprokiSection, buf, "UNKNOWN");
		if(strBuf != "UNKNOWN")
		{
			nCounter++;
		}
		else
		{
			break;
		}
	}

	if(g_szCryptoKiPaths)
	{
		delete [] g_szCryptoKiPaths;
		g_szCryptoKiPaths = NULL;
	}

	if(pos)
	{
		delete [] pos;
		pos = NULL;
	}

	if(modhandles)
	{
		free(modhandles);
		modhandles = NULL;
	}

	g_szCryptoKiPaths = new string[nCounter];
	if(!g_szCryptoKiPaths)
	{
		return CKR_GENERAL_ERROR;
	}

	for(int i = 0; i < nCounter; i++)
	{
		g_szCryptoKiPaths[i] = "";
	}

	nCounter = 0;
	while(true)
	{
		sprintf(buf, "%s%d", g_strCryprokiPrefix, nCounter);

		strBuf = reader.Get(g_strCryprokiSection, buf, "UNKNOWN");
		if(strBuf != "UNKNOWN")
		{
			g_szCryptoKiPaths[nCounter] = strBuf;
			nCounter++;
		}
		else
		{
			break;
		}
	}

	modhandles = (void **) calloc(nCounter, sizeof(void *));
	if(!modhandles)
	{
		return CKR_GENERAL_ERROR;
	}

	pos = new CK_FUNCTION_LIST_PTR[nCounter];
	if(!pos)
	{
		return CKR_GENERAL_ERROR;
	}

	bool bAtLeastLoadedOneCryptoki = false;
	g_nCryptoKiCount = 0;

	p11_log(string_format("Cryptokis' Multiplexer - Version = %d.%d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_MINOR_2, VERSION_MINOR_3));

	g_bIsThereAnyChangesInModuless = false;

	for(int i = 0; i < nCounter; i++)
	{
		strcpy(temp_path, g_szCryptoKiPaths[i].c_str());
		module = temp_path;
		modhandles[i] = loadp11module(module, &pos[i]);
		g_vLastCryptoKiPaths.push_back(g_szCryptoKiPaths[i]);
	
		if(modhandles[i] && pos[i]) 
		{
			p11_log(string_format("Loaded: \"%s\"\n", module));
			bAtLeastLoadedOneCryptoki = true;
			g_nCryptoKiCount++;
		} 
		else 
		{
			g_nCryptoKiCount++;
			pos[i] = NULL;
		}
	}

	if(!bAtLeastLoadedOneCryptoki)
	{
		free(p11_multiplex);
		rv = CKR_GENERAL_ERROR;
	}

	return rv;
}

static void enter(const char *function)
{
	static int count = 0;
	char strFileName[FILENAME_MAX + 1] = {0};
	time_t rawtime;
	struct tm * timeinfo;
	char buffer [80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime (buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

#ifdef _WIN32
	GetModuleFileName(NULL, strFileName, FILENAME_MAX);
#else
	strcpy(strFileName, dl_info.dli_fname);
#endif

	unsigned int PId;
	unsigned int ThId;
#ifdef _WIN32
	PId = GetCurrentProcessId();
	ThId = GetCurrentThreadId();
#else
	PId = getpid();
	ThId = pthread_self();
#endif

	p11_log(string_format("\n--------------------------------\n"), true);
	p11_log(string_format("%d: %s : Process : %s(PID : %u : TID : %u)\n", count++, buffer, strFileName, PId, ThId));
	p11_log(string_format("%s\n", function));
}

static CK_RV retne(CK_RV rv, int Seed = -1)
{
	if (Seed == -1)
		p11_log(string_format("Returned:  %lu %s\n", rv, lookup_enum(RV_T, rv)));
	else
		p11_log(string_format("[%x] Returned:  %lu %s\n", Seed, rv, lookup_enum(RV_T, rv)));

	return rv;
}

static void p11mpx_dump_string_in(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
	p11_log(string_format("[in] %s ", name));

	print_generic(0, data, size, NULL);
}

static void p11mpx_dump_string_out(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
	p11_log(string_format("[out] %s ", name));

	print_generic(0, data, size, NULL);
}

static void p11mpx_dump_ulong_in(const char *name, CK_ULONG value)
{
	p11_log(string_format("[in] %s = 0x%lx\n", name, value));
}

static void p11mpx_dump_ulong_out(const char *name, CK_ULONG value)
{
	p11_log(string_format("[out] %s = 0x%lx\n", name, value));
}

static void p11mpx_dump_desc_out(const char *name)
{
	p11_log(string_format("[out] %s: \n", name));
}

static void p11mpx_dump_array_out(const char *name, CK_ULONG size)
{
	p11_log(string_format("[out] %s[%ld]: \n", name, size));
}

static void p11mpx_attribute_req_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulCount)
{
	p11_log(string_format("[in] %s[%ld]: \n", name, ulCount));

	print_attribute_list_req(pTemplate, ulCount);
}

static void p11mpx_attribute_list_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulCount)
{
	p11_log(string_format("[in] %s[%ld]: \n", name, ulCount));

	print_attribute_list(pTemplate, ulCount);
}

static void p11mpx_attribute_list_out(const char *name, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulCount)
{
	p11_log(string_format("[out] %s[%ld]: \n", name, ulCount));

	print_attribute_list(pTemplate, ulCount);
}

static void print_ptr_in(const char *name, CK_VOID_PTR ptr)
{
	p11_log(string_format("[in] %s = %p\n", name, ptr));
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	bool bNoFunPointerAvail = false;

	for(int i = 0; i < g_nCryptoKiCount; i++)
	{
		if(pos[i] != NULL)
			bNoFunPointerAvail = true;
	}

	if(!bNoFunPointerAvail) 
	{
		CK_RV rv = init_p11mpx();

		if (rv != CKR_OK)
			return retne(rv);
	}

	*ppFunctionList = p11_multiplex;

	return retne(CKR_OK);
}

static CK_RV CheckforChangesinModules()
{
	g_vChangedCryptoKiPaths.clear();
	string strConfPath = "";
	char strModulePath[FILENAME_MAX] = { 0 };
	size_t unFound = 0;

#ifdef _WIN32
	GetModuleFileName((HINSTANCE)&__ImageBase, strModulePath, _countof(strModulePath));
	strConfPath = string(strModulePath);
	unFound = strConfPath.find_last_of(".");
	strConfPath = strConfPath.substr(0, unFound) + string(".cfg");
#else
	strConfPath = string(dl_info.dli_fname);
	unFound = strConfPath.rfind('.');
	strConfPath = strConfPath.substr(0, unFound) + string(".cfg");
#endif

	int nCounter = 0;
	char buf[FILENAME_MAX * 2];

	INIReader reader;
	if(!g_bIsStaticConf)
	{
		reader.SetConfig(strConfPath, g_bIsStaticConf);
	}
	else
	{
		reader.SetConfig(g_strCryptokiConf, g_bIsStaticConf);
	}

	if(reader.ParseError() < 0)
	{
		return CKR_GENERAL_ERROR;
	}

	string strBuf = "";

	while(true)
	{
		sprintf(buf, "%s%d", g_strCryprokiPrefix, nCounter);
		strBuf = reader.Get(g_strCryprokiSection, buf, "UNKNOWN");
		if (strBuf != "UNKNOWN")
		{
			if (std::find(g_vLastCryptoKiPaths.begin(), g_vLastCryptoKiPaths.end(), strBuf) == g_vLastCryptoKiPaths.end())
			{
				g_vChangedCryptoKiPaths.push_back(strBuf);
				g_bIsThereAnyChangesInModuless = true;
			}
			else
			{

			}
			nCounter++;
		}
		else
		{
			break;
		}
	}

	return retne(CKR_OK);
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	enter("C_Initialize");
	print_ptr_in("pInitArgs", pInitArgs);

	CK_RV rv, tRV = 0;
	rv = CKR_OK;

	bool AllReturnOneError = true;
	bool bNoFunPointerAvail = false;
	bool bAtLeastLoadedOneCryptoki = false;

	CheckforChangesinModules();

	if(g_bAlreadyInited && g_bIsThereAnyChangesInModuless == false)
		return retne(CKR_CRYPTOKI_ALREADY_INITIALIZED);

#ifdef _WIN32
	if(!InitializeCriticalSectionAndSpinCount(&SessionCriticalSection, 0x400))
		return retne(CKR_FUNCTION_FAILED);

	if(!InitializeCriticalSectionAndSpinCount(&SlotCriticalSection, 0x400))
		return retne(CKR_FUNCTION_FAILED);
#endif

	for(int i = 0; i < g_nCryptoKiCount; i++)
	{
		if(pos[i] != NULL)
			bNoFunPointerAvail = true;
	}

	if(!bNoFunPointerAvail) 
	{
		rv = init_p11mpx();
		if (rv != CKR_OK)
			return retne(rv);
	}
	if (g_bIsThereAnyChangesInModuless == false)
	{

		bAtLeastLoadedOneCryptoki = false;
		for(int i = 0; i < g_nCryptoKiCount; i++)
		{
			if (pos[i])
			{
				rv = pos[i]->C_Initialize(pInitArgs);
				if (rv == CKR_OK)
				{
					bAtLeastLoadedOneCryptoki = true;
					p11_log(string_format("Initializing module \"%s\" is successful\n", g_vLastCryptoKiPaths.at(i).c_str()));
				}
				else
				{
					if((i != 0) && (tRV != rv))
					{
						AllReturnOneError = false;
					}
					tRV = rv;

					p11_log(string_format("Initializing module \"%s\" failed with code : %x\n", g_vLastCryptoKiPaths.at(i).c_str(), rv));
				}
			}
			else
				p11_log(string_format("Initializing module \"%s\" failed with code : %x\n", g_vLastCryptoKiPaths.at(i).c_str(), rv));
		}

		if(bAtLeastLoadedOneCryptoki)
			rv = CKR_OK;
		else
			rv = CKR_GENERAL_ERROR;
	}
	else
	{
		p11_log(string_format("Changes detected in modules\n"));
		void **tempmodhandles = NULL;
		CK_FUNCTION_LIST_PTR *temppos = NULL;

		if(tempmodhandles)
		{
			free(tempmodhandles);
			tempmodhandles = NULL;
		}

		if(temppos)
		{
			delete[] temppos;
			temppos = NULL;
		}

		tempmodhandles = (void **) calloc(g_vChangedCryptoKiPaths.size(), sizeof(void *));
		if(!tempmodhandles)
		{
			return retne(CKR_GENERAL_ERROR);
		}

		temppos = new CK_FUNCTION_LIST_PTR[g_vChangedCryptoKiPaths.size() + g_vLastCryptoKiPaths.size()];
		if (!temppos)
		{
			return retne(CKR_GENERAL_ERROR);
		}

		for(unsigned int i = 0; i < g_vLastCryptoKiPaths.size(); i++)
		{
			temppos[i] = pos[i];
		}

		bAtLeastLoadedOneCryptoki = false;
		for(unsigned int i = 0; i < g_vChangedCryptoKiPaths.size(); i++)
		{

			tempmodhandles[i] = loadp11module(g_vChangedCryptoKiPaths.at(i).c_str(), &temppos[g_vLastCryptoKiPaths.size() + i]);

			if (tempmodhandles[i] && temppos[g_vLastCryptoKiPaths.size() + i])
			{
				rv = temppos[g_vLastCryptoKiPaths.size() + i]->C_Initialize(pInitArgs);
				if (rv != CKR_OK)
					p11_log(string_format("Adding Module: \"%s\" is failed with code : %x\n", g_vChangedCryptoKiPaths.at(i).c_str(),rv));
				else
				{
					p11_log(string_format("Adding Module: \"%s\" is successful\n", g_vChangedCryptoKiPaths.at(i).c_str()));
					g_vLastCryptoKiPaths.push_back(g_vChangedCryptoKiPaths.at(i));
					bAtLeastLoadedOneCryptoki = true;
				}

				g_nCryptoKiCount++;
			}
			else
			{
				p11_log(string_format("Adding Module: \"%s\" is failed with code : %x\n", g_vChangedCryptoKiPaths.at(i).c_str(), rv));
				g_nCryptoKiCount++;
				temppos[g_vLastCryptoKiPaths.size() + i] = NULL;
			}
		}

		g_vChangedCryptoKiPaths.clear();
		g_bIsThereAnyChangesInModuless = false;

		if(tempmodhandles)
			free(tempmodhandles);

		if(pos)
			delete[] pos;

		pos = temppos;
		if(!bAtLeastLoadedOneCryptoki && g_vLastCryptoKiPaths.size() == 0)
		{
			free(p11_multiplex);
			rv = CKR_GENERAL_ERROR;
			return retne(rv);
		}
		else
		{
			rv = CKR_OK;
			return retne(rv);
		}
	}

	if(rv == CKR_OK)
		g_bAlreadyInited = true;

	return retne(rv);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV rv = CKR_OK;
	enter("C_Finalize");

	if(pReserved == NULL)
	{
		gExt_bExitThread = true;
		for(int i = 0; i < g_nCryptoKiCount; i++)
		{
			if (pos[i])
			{
				pos[i]->C_Finalize(pReserved);
			}
		}

		g_bAlreadyInited = false;
		return retne(rv);
	}
	else
	{
		CK_SLOT_ID slotID = *((CK_SLOT_ID*)(pReserved));
		int posIndex = -1;
		CK_SLOT_ID nSlotCounts = 0;

		for(int i = 0; i < g_nCryptoKiCount; i++)
		{
			if(pos[i])
			{
				unsigned long nCurrentCryptoSlotCount = 0;
				pos[i]->C_GetSlotList(CK_FALSE, NULL, &nCurrentCryptoSlotCount);
				nSlotCounts += nCurrentCryptoSlotCount;

				if(slotID < nSlotCounts)
				{
					posIndex = i;
					break;
				}
			}
		}

		if(posIndex == -1)
		{
			p11_log(string_format("Cannot Find Any Module for Slot ID %d\n", slotID));
			return retne(CKR_GENERAL_ERROR);
		}
		else
		{
			p11_log(string_format("Finalizing Module : %s\n", g_vLastCryptoKiPaths.at(posIndex).c_str()));
			CK_FUNCTION_LIST_PTR *temppos = NULL;
			if(temppos)
			{
				delete[] temppos;
				temppos = NULL;
			}

			temppos = new CK_FUNCTION_LIST_PTR[g_nCryptoKiCount-1];
			if(!temppos)
			{
				return retne(CKR_GENERAL_ERROR);
			}

			int j = -1;

			for(int i = 0; i < g_nCryptoKiCount; i++)
			{
				if(i == posIndex)
					continue;
				else
					j++;

				temppos[j] = pos[i];
			}

			pos[posIndex]->C_Finalize(NULL);
			if (pos)
				delete[] pos;

			pos = temppos;
			g_nCryptoKiCount--;
			g_vLastCryptoKiPaths.erase(g_vLastCryptoKiPaths.begin() + posIndex);
			g_bIsThereAnyChangesInModuless = true;
		}

		return retne(CKR_OK);
	}

}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	CK_RV rv;
	enter("C_GetInfo");

	if(pInfo == NULL)
		return retne(CKR_ARGUMENTS_BAD);

	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 1;
	pInfo->flags = 0;

	memcpy(pInfo->libraryDescription, MULTIPLEXER_LIBRARY_DESCRIPTION, 32);

	pInfo->libraryVersion.major = VERSION_MAJOR;
	pInfo->libraryVersion.minor = VERSION_MINOR;

	memcpy(pInfo->manufacturerID, MULTIPLEXER_MANUFACTURERID, 32);

	rv = CKR_OK;
	return retne(rv);
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	enter("C_GetSlotList");
	p11mpx_dump_ulong_in("tokenPresent", tokenPresent);

#ifdef _WIN32
	EnterCriticalSection(&SlotCriticalSection);
#endif
	rv = updatSlotLists();

	if(rv == CKR_OK)
	{
		CK_ULONG			ulPresents = 0;
		CK_SLOT_ID_PTR	pPresentIDs = NULL, pAllIDs = NULL;
		pPresentIDs = (CK_SLOT_ID_PTR) malloc(g_vCryptoMaps.size() * sizeof(CK_SLOT_ID));
		pAllIDs = (CK_SLOT_ID_PTR) malloc(g_vCryptoMaps.size() * sizeof(CK_SLOT_ID));
		for(size_t j = 0; j < g_vCryptoMaps.size(); j++)
		{
			if(g_vCryptoMaps[j].bIsPresent)
			{
				ulPresents++;
				pPresentIDs[ulPresents - 1] = g_vCryptoMaps[j].ulSlotId;
			}

			pAllIDs[j] = g_vCryptoMaps[j].ulSlotId;
		}

		if(tokenPresent)
			*pulCount = ulPresents;// + 1;
		else
			*pulCount = (CK_ULONG) g_vCryptoMaps.size();

		if(pSlotList)
		{
			memcpy(pSlotList, (tokenPresent ? pPresentIDs: pAllIDs), (sizeof(CK_SLOT_ID) * (tokenPresent ? ulPresents : g_vCryptoMaps.size())));
		}
	}

#ifdef _WIN32
	LeaveCriticalSection(&SlotCriticalSection);
#endif

	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_desc_out("pSlotList");
			print_slot_list(pSlotList, *pulCount);
			p11mpx_dump_ulong_out("*pulCount", *pulCount);
		}
	}

	return retne(rv);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;
	enter("C_GetSlotInfo");
	p11mpx_dump_ulong_in("slotID", slotID);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	rv = getPOFromSlotID(slotID)->C_GetSlotInfo(getRealSlotID(slotID), pInfo);

	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_desc_out("pInfo");
			print_slot_info(pInfo);
		}
	}
	return retne(rv);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	enter("C_GetTokenInfo");
	p11mpx_dump_ulong_in("slotID", slotID);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	p11_log(string_format("GetTokenInfo realslot %d \n", getRealSlotID(slotID)));

	rv = getPOFromSlotID(slotID)->C_GetTokenInfo(getRealSlotID(slotID), pInfo);

	p11_log(string_format("GetTokenInfo returned %d \n", rv));

	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_desc_out("pInfo");
			print_token_info(pInfo);
		}
	}
	return retne(rv);
}

CK_RV C_GetMechanismList(CK_SLOT_ID  slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR  pulCount)
{
	CK_RV rv;
	enter("C_GetMechanismList");
	p11mpx_dump_ulong_in("slotID", slotID);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	rv = getPOFromSlotID(slotID)->C_GetMechanismList(getRealSlotID(slotID), pMechanismList, pulCount);
	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_array_out("pMechanismList", *pulCount);
			print_mech_list(pMechanismList, *pulCount);
		}
	}
	return retne(rv);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID  slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	const char *name = lookup_enum(MEC_T, type);
	enter("C_GetMechanismInfo");
	p11mpx_dump_ulong_in("slotID", slotID);

	if(g_bEnableLog)
	{
		if (name)
		{
			p11_log(string_format("%30s \n",name));
		}
		else 
		{
			p11_log(string_format(" Unknown Mechanism (%08lx)  \n",type));
		}
	}


	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	rv = getPOFromSlotID(slotID)->C_GetMechanismInfo(getRealSlotID(slotID), type, pInfo);
	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_desc_out("pInfo");
			print_mech_info(type, pInfo);
		}
	}

	return retne(rv);
}

CK_RV C_InitToken (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv;
	enter("C_InitToken");
	p11mpx_dump_ulong_in("slotID", slotID);
	p11mpx_dump_string_in("pLabel[32]", pLabel, 32);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	rv = getPOFromSlotID(slotID)->C_InitToken(getRealSlotID(slotID), pPin, ulPinLen, pLabel);

	return retne(rv);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG  ulPinLen)
{
	CK_RV rv;
	enter("C_InitPIN");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_InitPIN(hSession, pPin, ulPinLen);
	return retne(rv);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG  ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG  ulNewLen)
{
	CK_RV rv;
	enter("C_SetPIN");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pOldPin[ulOldLen]", pOldPin, ulOldLen);
	p11mpx_dump_string_in("pNewPin[ulNewLen]", pNewPin, ulNewLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	return retne(rv);
}

CK_RV C_OpenSession(CK_SLOT_ID  slotID, CK_FLAGS  flags, CK_VOID_PTR  pApplication, CK_NOTIFY  Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv;
	enter("C_OpenSession");
	if(g_bEnableLog)
	{
		p11mpx_dump_ulong_in("slotID", slotID);
		p11mpx_dump_ulong_in("flags", flags);
		p11_log(string_format("pApplication=%p\n",pApplication));
		p11_log(string_format("Notify=%p\n",(void *)Notify));
	}

#ifdef _WIN32
	EnterCriticalSection(&SlotCriticalSection);
#endif

	// to check
	for(unsigned int i = 0; i < g_vSessionMaps.size(); i++)
	{
		if(g_vSessionMaps[i].vulFakeSession.size() == 0)
		{
			g_vSessionMaps.erase(g_vSessionMaps.begin()+i);
			i--;
		}
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SLOT_ID_INVALID);
	}

	CK_SLOT_ID	ulRealSlotID = getRealSlotID(slotID);

	rv = pFunc->C_OpenSession(ulRealSlotID, flags, pApplication, Notify, phSession);
	if(rv == CKR_OK)
	{
		CK_SESSION_HANDLE fakeValue = *phSession;
		for(unsigned int i = 0; i < g_vSessionMaps.size(); i++)
		{
			for(size_t j = 0; j < g_vSessionMaps[i].vulSession.size(); j++)
			{
				if(g_vSessionMaps[i].vulSession[j] == *phSession)
				{
					fakeValue += 1;
				}
			}
		}

		updateSession(slotID, *phSession, fakeValue);
		*phSession = fakeValue;
	}

#ifdef _WIN32
	LeaveCriticalSection(&SlotCriticalSection);
#endif

	p11mpx_dump_ulong_out("*phSession", *phSession);

	return retne(rv);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	enter("C_CloseSession");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_CloseSession(hSession);
#ifdef _WIN32
	EnterCriticalSection(&SlotCriticalSection);
#endif

	if(rv == CKR_OK)
		updateSession2(hSession, 0);	//warning linux

#ifdef _WIN32
	LeaveCriticalSection(&SlotCriticalSection);
#endif

	return retne(rv);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv;
	enter("C_CloseAllSessions");
	p11mpx_dump_ulong_in("slotID", slotID);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSlotID(slotID);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = getPOFromSlotID(slotID)->C_CloseAllSessions(getRealSlotID(slotID));
	closeAllSession(slotID);
	return retne(rv);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv;
	enter("C_GetSessionInfo");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GetSessionInfo(hSession, pInfo);
	if(rv == CKR_OK) 
	{
		if(g_bEnableLog)
		{
			p11mpx_dump_desc_out("pInfo");
			print_session_info(pInfo);
		}
	}
	return retne(rv);
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;
	enter("C_GetOperationState");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GetOperationState(hSession, pOperationState, pulOperationStateLen);

	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pOperationState[*pulOperationStateLen]",
				pOperationState, *pulOperationStateLen);
	}

	return retne(rv);
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG  ulOperationStateLen,CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;
	enter("SetOperationState");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pOperationState[ulOperationStateLen]", pOperationState, ulOperationStateLen);
	p11mpx_dump_ulong_in("hEncryptionKey", hEncryptionKey);
	p11mpx_dump_ulong_in("hAuthenticationKey", hAuthenticationKey);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);

	return retne(rv);
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG  ulPinLen)
{
	CK_RV rv;
	enter("C_Login");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11_log(string_format("[in] userType = %s\n",lookup_enum(USR_T, userType)));

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Login(hSession, userType, pPin, ulPinLen);
	return retne(rv);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	enter("C_Logout");
	p11mpx_dump_ulong_in("hSession", hSession);


	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Logout(hSession);
	return retne(rv);
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;
	enter("C_CreateObject");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_attribute_list_in("pTemplate", pTemplate, ulCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_CreateObject(hSession, pTemplate, ulCount, phObject);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("*phObject", *phObject);
	}
	return retne(rv);
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv;
	enter("C_CopyObject");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hObject", hObject);
	p11mpx_attribute_list_in("pTemplate", pTemplate, ulCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	if(rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("*phNewObject", *phNewObject);
	}

	return retne(rv);
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	enter("C_DestroyObject");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hObject", hObject);
	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DestroyObject(hSession, hObject);
	return retne(rv);
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	CK_RV rv;
	enter("C_GetObjectSize");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hObject", hObject);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GetObjectSize(hSession, hObject, pulSize);

	if(rv == CKR_OK)
	{
		p11mpx_dump_ulong_out("*pulSize", *pulSize);
	}

	return retne(rv);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_RV rv;
	enter("C_GetAttributeValue");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hObject", hObject);
	p11mpx_attribute_req_in("pTemplate", pTemplate, ulCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
	if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
			rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL) 
	{
		p11mpx_attribute_list_out("pTemplate", pTemplate, ulCount);
	}

	return retne(rv);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulCount)
{
	CK_RV rv;
	enter("C_SetAttributeValue");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hObject", hObject);
	p11mpx_attribute_list_in("pTemplate", pTemplate, ulCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
	return retne(rv);
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_RV rv;
	enter("C_FindObjectsInit");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_attribute_list_in("pTemplate", pTemplate, ulCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_FindObjectsInit(hSession, pTemplate, ulCount);
	return retne(rv);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG  ulMaxObjectCount, CK_ULONG_PTR  pulObjectCount)
{
	CK_RV rv;
	enter("C_FindObjects");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("ulMaxObjectCount", ulMaxObjectCount);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_FindObjects(hSession, phObject, ulMaxObjectCount,
			pulObjectCount);
	if (rv == CKR_OK) 
	{
		CK_ULONG          i;
		p11mpx_dump_ulong_out("ulObjectCount", *pulObjectCount);

		for (i = 0; i < *pulObjectCount; i++) 
		{
			p11_log(string_format("Object 0x%lx matches\n",phObject[i]));			
		}
	}
	return retne(rv);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	enter("C_FindObjectsFinal");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_FindObjectsFinal(hSession);
	return retne(rv);
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_EncryptInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_EncryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;
	enter("C_Encrypt");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pData[ulDataLen]", pData, ulDataLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pEncryptedData[*pulEncryptedDataLen]",
				pEncryptedData, *pulEncryptedDataLen);
	}

	return retne(rv);
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	enter("C_EncryptUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);
	}
	return retne(rv);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	enter("C_EncryptFinal");
	p11mpx_dump_ulong_in("hSession", hSession);
	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
	if (rv == CKR_OK) {
		p11mpx_dump_string_out("pLastEncryptedPart[*pulLastEncryptedPartLen]",
				pLastEncryptedPart, *pulLastEncryptedPartLen);
	}
	return retne(rv);
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_DecryptInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DecryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG  ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	enter("C_Decrypt");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pEncryptedData[ulEncryptedDataLen]", pEncryptedData, ulEncryptedDataLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	if (rv == CKR_OK) {
		p11mpx_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
	}
	return retne(rv);
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG  ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	enter("C_DecryptUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv == CKR_OK) {
		p11mpx_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
	}
	return retne(rv);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;
	enter("C_DecryptFinal");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pLastPart[*pulLastPartLen]", pLastPart, *pulLastPartLen);
	}

	return retne(rv);
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_DigestInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DigestInit(hSession, pMechanism);
	return retne(rv);
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	enter("C_Digest");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pData[ulDataLen]", pData, ulDataLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pDigest[*pulDigestLen]",
				pDigest, *pulDigestLen);
	}
	return retne(rv);
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen)
{
	CK_RV rv;
	enter("C_DigestUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DigestUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	enter("C_DigestKey");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_ulong_in("hKey", hKey);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DigestKey(hSession, hKey);
	return retne(rv);
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	enter("C_DigestFinal");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DigestFinal(hSession, pDigest, pulDigestLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pDigest[*pulDigestLen]",
				pDigest, *pulDigestLen);
	}
	return retne(rv);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_SignInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	enter("C_Sign");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pData[ulDataLen]", pData, ulDataLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pSignature[*pulSignatureLen]",
				pSignature, *pulSignatureLen);
	}
	return retne(rv);
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen)
{
	CK_RV rv;
	enter("C_SignUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	enter("C_SignFinal");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignFinal(hSession, pSignature, pulSignatureLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pSignature[*pulSignatureLen]",
				pSignature, *pulSignatureLen);
	}
	return retne(rv);
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_SignRecoverInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignRecoverInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG  ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	enter("C_SignRecover");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pData[ulDataLen]", pData, ulDataLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pSignature[*pulSignatureLen]",
				pSignature, *pulSignatureLen);
	}
	return retne(rv);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_VerifyInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_VerifyInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG  ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG  ulSignatureLen)
{
	CK_RV rv;
	enter("C_Verify");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	p11mpx_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	return retne(rv);
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG  ulPartLen)
{
	CK_RV rv;
	enter("C_VerifyUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_VerifyUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG  ulSignatureLen)
{
	CK_RV rv;
	enter("C_VerifyFinal");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pSignature[ulSignatureLen]",
			pSignature, ulSignatureLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	return retne(rv);
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_VerifyRecoverInit");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_VerifyRecoverInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG  ulSignatureLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	enter("C_VerifyRecover");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pSignature[ulSignatureLen]",
			pSignature, ulSignatureLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
	}
	return retne(rv);
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	enter("C_DigestEncryptUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
				pEncryptedPart, *pulEncryptedPartLen);
	}

	return retne(rv);
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	enter("C_DecryptDigestUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
			pEncryptedPart, ulEncryptedPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart,  pulPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
	}
	return retne(rv);
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	enter("C_SignEncryptUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
				pEncryptedPart, *pulEncryptedPartLen);
	}
	return retne(rv);
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	enter("C_DecryptVerifyUpdate");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DecryptVerifyUpdate(hSession, pEncryptedPart,
			ulEncryptedPartLen, pPart,
			pulPartLen);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
	}
	return retne(rv);
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulCount,
		CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_GenerateKey");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_attribute_list_in("pTemplate", pTemplate, ulCount);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("hKey", *phKey);
	}
	return retne(rv);
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG  ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG  ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_GenerateKeyPair");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_attribute_list_in("pPublicKeyTemplate", pPublicKeyTemplate, ulPublicKeyAttributeCount);
		p11mpx_attribute_list_in("pPrivateKeyTemplate", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate,
			ulPublicKeyAttributeCount, pPrivateKeyTemplate,
			ulPrivateKeyAttributeCount, phPublicKey,
			phPrivateKey);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("hPublicKey", *phPublicKey);
		p11mpx_dump_ulong_out("hPrivateKey", *phPrivateKey);
	}

	return retne(rv);
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_WrapKey");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hWrappingKey", hWrappingKey);
		p11mpx_dump_ulong_in("hKey", hKey);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);

	if (rv == CKR_OK) 
	{
		p11mpx_dump_string_out("pWrappedKey[*pulWrappedKeyLen]",
				pWrappedKey, *pulWrappedKeyLen);
	}
	return retne(rv);
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey,
		CK_BYTE_PTR  pWrappedKey,
		CK_ULONG  ulWrappedKeyLen,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulAttributeCount,
		CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_UnwrapKey");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hUnwrappingKey", hUnwrappingKey);
		p11mpx_dump_string_in("pWrappedKey[ulWrappedKeyLen]", pWrappedKey, ulWrappedKeyLen);
		p11mpx_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey,
			pWrappedKey, ulWrappedKeyLen, pTemplate,
			ulAttributeCount, phKey);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("hKey", *phKey);
	}
	return retne(rv);
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG  ulAttributeCount,
		CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	if(g_bEnableLog)
	{
		enter("C_DeriveKey");
		p11mpx_dump_ulong_in("hSession", hSession);
		p11_log(string_format("pMechanism->type=%s\n",lookup_enum(MEC_T, pMechanism->mechanism)));
		p11mpx_dump_ulong_in("hBaseKey", hBaseKey);
		p11mpx_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
	}

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
	if (rv == CKR_OK) 
	{
		p11mpx_dump_ulong_out("hKey", *phKey);
	}
	return retne(rv);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSeed,
		CK_ULONG  ulSeedLen)
{
	CK_RV rv;
	enter("C_SeedRandom");
	p11mpx_dump_ulong_in("hSession", hSession);
	p11mpx_dump_string_in("pSeed[ulSeedLen]", pSeed, ulSeedLen);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_SeedRandom(hSession, pSeed, ulSeedLen);
	return retne(rv);
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR RandomData,
		CK_ULONG  ulRandomLen)
{
	CK_RV rv;
	enter("C_GenerateRandom");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GenerateRandom(hSession, RandomData, ulRandomLen);
	if (rv == CKR_OK)
	{
		p11mpx_dump_string_out("RandomData[ulRandomLen]",
				RandomData, ulRandomLen);
	}
	return retne(rv);
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	enter("C_GetFunctionStatus");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_GetFunctionStatus(hSession);
	return retne(rv);
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	enter("C_CancelFunction");
	p11mpx_dump_ulong_in("hSession", hSession);

	CK_FUNCTION_LIST_PTR pFunc = getPOFromSession(&hSession);
	if(!pFunc)
	{
		return retne(CKR_SESSION_HANDLE_INVALID);
	}

	rv = pFunc->C_CancelFunction(hSession);
	return retne(rv);
}

#ifdef _WIN32
DWORD WINAPI waitThread(LPVOID pArgs_)
{
	CK_SLOT_ID wSlot = 0;
	int tC = 0;
	BOOL bRet = FALSE, ownedCS = FALSE;
	int ret = 0;
	int index = ((Thread_Args*) pArgs_)->index;
	int seed = ((Thread_Args*) pArgs_)->Seed;
	CK_FLAGS flg = ((Thread_Args*) pArgs_)->taskflags;

	p11_log(string_format("C_WaitForSlotEvent in CryptoKi %d Starts\n", index), false, seed);

	ret = pos[index]->C_WaitForSlotEvent(flg, &(wSlot), NULL);
	if(ret == CKR_OK)
	{
		tC = 0;
		while(1)
		{
			ownedCS = TRUE;
			bRet = TryEnterCriticalSection(&CriticalSection);
			if(bRet == TRUE)
				break;

			if(tC > MAX_WAIT_FOR_CS)
			{
				ownedCS = FALSE;
				break;
			}
			Sleep(1);
			tC++;

		}
		g_CryptSlotArray[g_CryptSlotArrayPtr].cryptokiNum = index;
		g_CryptSlotArray[g_CryptSlotArrayPtr].slotNum = wSlot;
		g_CryptSlotArrayPtr++;

		if(ownedCS == TRUE)
			LeaveCriticalSection(&CriticalSection);
	}
	else if(ret == CKR_NO_EVENT)
	{
		p11_log(string_format("CryptoKi %d Returend CKR_NO_EVENT\n", index), false, seed);
	}
	else
	{
		if(ret == CKR_FUNCTION_NOT_SUPPORTED)
			g_bAnyThreadError = true;

		p11_log(string_format("CryptoKi %d Failed: %d\n", index, ret), false, seed);
	}

	return 0;
}
#endif

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
		CK_SLOT_ID_PTR pSlot,
		CK_VOID_PTR pRserved)
{
	int i = 0, j = 0, k = 0, ret = 0;
	int tC = 0;
	bool isLastStackEmpty = false;
	bool result = false;
	int nSlotCounts = 0;
	int index = 0;
	CK_SLOT_ID wSlot = 0;
	CK_SLOT_ID slotID = 0;
	BOOL bRet = FALSE, ownedCS = TRUE;
	HANDLE threadHdl[MAX_EVENT_ARRAY_SIZE] = {NULL};

	unsigned long nCurrentCryptoSlotCount = 0;
	srand((unsigned int) time(NULL));
	int Seed = rand() % 65530 + 1;

	enter((string_format("[%x] ", Seed) + "C_WaitForSlotEvent").c_str());
	p11_log(string_format("\t[in] flags %d\n", flags), false, Seed);
	p11_log(string_format("\t[in] Total CryptoKi %d\n", g_nCryptoKiCount), false, Seed);

	g_bAnyThreadError = false;

	if(gExt_bExitThread)
		return retne(CKR_FUNCTION_NOT_SUPPORTED, Seed);

	if(!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x400))
		return retne(CKR_FUNCTION_FAILED, Seed);

	if(g_CryptSlotArrayPtr == 0)
	{
		isLastStackEmpty = true;
		if (flags != CKF_DONT_BLOCK)
		{
			g_iWaitEventsCount = 0;
		}

		for(i = 0; i < g_nCryptoKiCount; i++)
		{
			if(gExt_bExitThread)
				return retne(CKR_NO_EVENT, Seed);

			if(pos[i] == NULL)
				continue;

			if(flags == CKF_DONT_BLOCK)
			{
				ret = pos[i]->C_WaitForSlotEvent(CKF_DONT_BLOCK, &wSlot, NULL);
				if(ret == CKR_OK)
				{
					g_CryptSlotArray[g_CryptSlotArrayPtr].cryptokiNum = i;
					g_CryptSlotArray[g_CryptSlotArrayPtr].slotNum = wSlot;
					g_CryptSlotArrayPtr++;
				}
				continue;
			}
			else
			{			
				Thread_Args *args = NULL;
				args = (Thread_Args *) calloc(1, sizeof(Thread_Args));	

				args->index = i;
				args->taskflags = flags;
				args->Seed = Seed;
				threadHdl[g_iWaitEventsCount] = CreateThread(NULL, 0, &waitThread, (LPVOID) args, 0, NULL);

				if(threadHdl[g_iWaitEventsCount] == NULL)
				{
					p11_log(string_format("CreateThread error: %d\n", GetLastError()), false, Seed);
					return retne(CKR_FUNCTION_FAILED, Seed);
				}
			}

			g_iWaitEventsCount++;
		}

		if(flags != CKF_DONT_BLOCK)
		{
			p11_log(string_format("Waiting Starts\n"), false, Seed);
WAIT_1:
			ret = WaitForMultipleObjects(g_iWaitEventsCount, threadHdl, FALSE, 1);
			if(ret == WAIT_FAILED)
			{
				p11_log(string_format("Wait failed error %x\n", GetLastError()), false, Seed);
				return retne(CKR_FUNCTION_FAILED, Seed);
			}

			if((ret >= (int) WAIT_ABANDONED_0) && (ret <= (int) (WAIT_ABANDONED_0 + g_iWaitEventsCount - 1)))
			{
				p11_log(string_format("Wait abandoned %d\n", ret), false, Seed);
			}

			if(ret == WAIT_TIMEOUT)
			{
				goto WAIT_1;
			}

			p11_log(string_format("Waiting Ends\n"), false, Seed);
		}

		if(g_bAnyThreadError)
			return retne(CKR_FUNCTION_NOT_SUPPORTED, Seed);

		if(flags != CKF_DONT_BLOCK)
		{
			tC = 0;
			while(1)
			{
				ownedCS = TRUE;
				bRet = TryEnterCriticalSection(&CriticalSection);
				if(bRet == TRUE)
					break;

				p11_log(string_format("Cannot enter to critical section %d\n", tC), false, Seed);
				if(tC > MAX_WAIT_FOR_CS)
				{
					ownedCS = FALSE;
					break;
				}

				Sleep(1);
				tC++;
			}

			for(i = 0;  i < g_iWaitEventsCount; i++)
			{
				ret  = WaitForSingleObject(threadHdl[i], 0);

				if(ret != WAIT_OBJECT_0)
				{
					if(ret != WAIT_TIMEOUT)
					{
						p11_log(string_format("Wait code is not time out %x\n", ret), false, Seed);
					}
					Sleep(rand() % 150);
					TerminateThread(threadHdl[i], 0);
				}
			}

			if(ownedCS == TRUE)
				LeaveCriticalSection(&CriticalSection);
		}

		p11_log(string_format("StackPtr %d\n", g_CryptSlotArrayPtr), false, Seed);

		if(g_bEnableLog)
		{
			if(g_CryptSlotArrayPtr != 0)
				p11_log(string_format("Availble Slots in Stack\n"), false, Seed);
			else
				p11_log(string_format("No Availble Slots in Stack\n"), false, Seed);
		}
	}

	if(g_CryptSlotArrayPtr > 0)
	{
		nSlotCounts = 0;
		index = g_CryptSlotArray[g_CryptSlotArrayPtr - 1].cryptokiNum;
		slotID = g_CryptSlotArray[g_CryptSlotArrayPtr - 1].slotNum;
		p11_log(string_format("Module Number %d\n", index), false, Seed);
		p11_log(string_format("Fake Slot ID %d\n", slotID), false, Seed);

		for(j = 0; j < index; j++)
		{
			if(pos[j])
			{
				nCurrentCryptoSlotCount = 0;
				pos[j]->C_GetSlotList(CK_FALSE, NULL, &nCurrentCryptoSlotCount);
				nSlotCounts += nCurrentCryptoSlotCount;
			}
		}

		g_CryptSlotArrayPtr --;

		*pSlot = nSlotCounts + slotID;

		p11_log(string_format("[out] *pSlot %d\n", *pSlot), false, Seed);

		DeleteCriticalSection(&CriticalSection);

		return retne(CKR_OK, Seed);
	}
	else
	{
		DeleteCriticalSection(&CriticalSection);
		return retne(CKR_NO_EVENT, Seed);
	}
}
