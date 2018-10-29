/* cryptokimpx_test.cpp

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

#include <windows.h>
#include <iostream>
#include <conio.h>
#include <stdio.h>
#include "pkcs11.h"
using namespace std;

HINSTANCE				g_hP11Library = NULL;
CK_C_GetFunctionList	g_symGetFunctionList = NULL;
CK_FUNCTION_LIST_PTR	g_pFunctionList = NULL;
char					g_strErrorBufCKR[140] = {0};
bool					g_bInited = false;

char *getPKCS11ErrorName(CK_RV ResVal);
int	menu();
void Start();
void Initialize();
void Finalize();
void GetSlotList();
void WaitForSlotEvent();
void WaitForSlotEventTEST();
void WaitForSlotEventTESTThread();

int main()
{
	int iOperation = 0;

	Start();

	do
	{
		iOperation = menu();

		switch(iOperation)
		{
		case 1:
			Initialize();
			break;
		case 2:
			GetSlotList();
			break;
		case 3:
			WaitForSlotEvent();
			break;
		case 4:
			WaitForSlotEventTEST();
		case 5:
			WaitForSlotEventTESTThread();
		case 6:
			Finalize();
			break;
		case 7:
			exit(0);
			break;

		default:
			break;
		}
	} while (iOperation != 0);

	return 0;
}

int menu()
{
	cout << endl;
	cout << " 1-C_Initialize" << endl;
	cout << " 2-C_GetSlotList(?,NULL)" << endl;
	cout << " 3-C_WaitForSlotEvent" << endl;
	cout << " 4-C_WaitForSlotEvent Endless TEST" << endl;
	cout << " 5-C_WaitForSlotEvent Threading" << endl;
	cout << " 6-C_Finalize" << endl;
	cout << " 7-Exit" << endl;
	cout << " ------------------------------" << endl << endl;
	cout << " Please select an operation: ";

	int res = 0;
	cin >> res;

	cout << endl;

	return res;
}

void waitThread(LPVOID pArgs_)
{
	cout << "Starting Thread." << endl;
	CK_SLOT_ID sltid = NULL;

	int iRet = (*g_pFunctionList).C_WaitForSlotEvent(!CKF_DONT_BLOCK, &sltid, NULL);
	if (iRet != CKR_OK)
	{
		cout << "ERROR : " << iRet << " : " << getPKCS11ErrorName(iRet) << endl;
	}
	else
		cout << "Slot : " << sltid << endl;
}

void WaitForSlotEventTESTThread()
{
	HANDLE a = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)waitThread, NULL, 0, NULL);

	cout << "Thread Created."<< endl;
	// _getch();
	TerminateThread(a, 0);
	CloseHandle(a);
	cout << "Thread Terminated." << endl;
}

void WaitForSlotEventTEST()
{
	CK_RV	iRet = 0;

	if(!g_bInited)
	{
		cout << "Cryptoki is not initialized." << endl;
		return;
	}

	for(int i = 0;; i++)
	{
		CK_SLOT_ID sltid = NULL;
		iRet = (*g_pFunctionList).C_WaitForSlotEvent(!CKF_DONT_BLOCK, &sltid, NULL);
		if(iRet != CKR_OK)
		{
			cout << "ERROR : " << iRet << " : " << getPKCS11ErrorName(iRet) << endl;
			break;
		}
		else
			cout << i << " - Get Slot : " << sltid << endl;
	}
}

void WaitForSlotEvent()
{
	CK_SLOT_ID	sltid = NULL;
	int			p = 0;
	CK_RV		iRet = 0;

	if(!g_bInited)
	{
		cout << "Cryptoki is not initialized." << endl;
		return;
	}

	cout << "0-Blocking 1-NonBlocking: ";
	cin >> p;

	if(p == 0)
		iRet = (*g_pFunctionList).C_WaitForSlotEvent(NULL, &sltid, NULL);
	else
		iRet = (*g_pFunctionList).C_WaitForSlotEvent(CKF_DONT_BLOCK, &sltid, NULL); 

	cout << "C_WaitForSlotEvent() is done." << endl << endl;
}

void GetSlotList()
{
	CK_BBOOL		true1 = TRUE;
	CK_BBOOL		false1 = FALSE;
	CK_TOKEN_INFO	info;
	CK_ULONG		ulCount;
	CK_RV			rv = 0;
	CK_SLOT_ID		*pSlotList = NULL;

	if(!g_bInited)
	{
		cout << "Cryptoki is not initialized." << endl;
		return;
	}

	rv = (*(g_pFunctionList)).C_GetSlotList(false1, NULL, &ulCount);
	if(rv != CKR_OK)
	{
		printf("\nERROR in C_GetSlotList(NULL) :%s\n", getPKCS11ErrorName(rv));
		// _getch();
		return;
	}

	pSlotList = new CK_SLOT_ID[ulCount];
	rv = (*(g_pFunctionList)).C_GetSlotList(false1, pSlotList, &ulCount);
	if(rv != CKR_OK)
	{
		printf("\nERROR in C_GetSlotList(false, Allocated Slot List) failed , rv =  %s\n", getPKCS11ErrorName(rv));
		// _getch();
		delete pSlotList;
		return;
	}

	printf("\nNumber of Slots: %lu\n", ulCount);

	for(CK_ULONG i = 0; i < ulCount; i++)
	{
		printf("Slot[%lu] ID is %lu\n", i, pSlotList[i]);
	}

	rv = (*(g_pFunctionList)).C_GetSlotList(true1, pSlotList, &ulCount);
	if(rv != CKR_OK)
	{
		printf("\nERROR in C_GetSlotList(true, Allocated Slot List) failed , rv =  %s\n", getPKCS11ErrorName(rv));
		// _getch();
		delete pSlotList;
		return;
	}

	printf("\nNumber of Slots with token inside: %lu\n", ulCount);

	for(CK_ULONG i = 0; i < ulCount; i++)
	{
		printf("CK_TOKEN_INFO for SlotID(%lu)\n", pSlotList[i]);

		printf(".....................TokenInfo.....................\n\n");

		rv = (*(g_pFunctionList)).C_GetTokenInfo(pSlotList[i], &info);
		if(rv != CKR_OK)
		{
			printf("\nERROR in GetTokenInfo: C_GetTokenInfo failed , rv =  %s\n ", getPKCS11ErrorName(rv));
			return;
		}

		char templbl[50], tempSN[50], tempModel[50], tempmanufacturerID[50];
		memset(templbl, 0x00, 50);
		memset(tempSN, 0x00, 50);
		memset(tempmanufacturerID, 0x00, 50);
		memset(tempModel, 0x00, 50);

		memcpy(templbl, info.label, 16);
		memcpy(tempSN, info.serialNumber, 16);
		memcpy(tempmanufacturerID, info.manufacturerID, 32);
		memcpy(tempModel, info.model, 16);

		printf("      label:                   %s\n", templbl);
		printf("      manufacturerID:          %s\n", tempmanufacturerID);
		printf("      model:                   %16.16s\n", tempModel);
		printf("      serialNumber:            %16.16s\n", tempSN);
		printf("      ulMaxPinLen:             %ld\n", info.ulMaxPinLen);
		printf("      ulMinPinLen:             %ld\n", info.ulMinPinLen);
		printf("      hardwareVersion:         %d.%d\n", info.hardwareVersion.major, info.hardwareVersion.minor);
		printf("      firmwareVersion:         %d.%d\n\n", info.firmwareVersion.major, info.firmwareVersion.minor);
	}

	return;
}

void Finalize()
{
	CK_RV iRet = 0;

	if(!g_bInited)
	{
		cout << "Cryptoki is not initialized." << endl;
		return;
	}

	iRet = (*g_pFunctionList).C_Finalize(NULL);
	if(iRet)
	{
		printf("\nERROR in C_Finalize :%s\n", getPKCS11ErrorName(iRet));
		// _getch();
		return;
	}

	cout << "Finalize() is done." << endl << endl;
}

void Initialize()
{
	CK_RV	iRet = 0;

	iRet = (*g_pFunctionList).C_Initialize(NULL);
	if(iRet)
	{
		printf("\nERROR in init: C_Initialize :%s\n", getPKCS11ErrorName(iRet));
		// _getch();
		return;
	}
	
	g_bInited = true;

	cout << "Initialize() is done." << endl << endl;
}

void Start()
{
	cout << "Loading Cryptokis' Multiplexer (cryotokimpx.dll)" << endl;

	g_hP11Library = LoadLibrary("cryptokimpx.dll");
	if(g_hP11Library == NULL)
	{
		printf("Cannot load the PKCS #11 dll\n");
		// _getch();
		return;
	}

	g_symGetFunctionList = (CK_C_GetFunctionList) GetProcAddress(g_hP11Library, "C_GetFunctionList");
	if(g_symGetFunctionList == NULL)
	{
		FreeLibrary(g_hP11Library);
		printf("\nERROR in init: cannot retrieve function list.\n");
		// _getch();
		return;
	}

	int iRet = g_symGetFunctionList(&g_pFunctionList);
	if(iRet)
	{
		printf("\nERROR in init: cannot get function list.\n");
		// _getch();
		return;
	}
}

char *getPKCS11ErrorName(CK_RV ResVal)
{
	switch (ResVal)
	{
	case CKR_OK: return "CKR_OK";
	case CKR_CANCEL: return "CKR_CANCEL";
	case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT: return "CKR_NO_EVENT";
	case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
	case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
	case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
	case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
	case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
	case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
	case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
	case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
	case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
	case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
	case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
	case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
	case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
	case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
	case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
	case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
	case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
	}

	sprintf_s(g_strErrorBufCKR, "Unknown return code 0x%X", ResVal);

	return g_strErrorBufCKR;
}