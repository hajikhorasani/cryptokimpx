/* dllmain.cpp

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

bool gExt_bExitThread = false;
bool gExt_bDllDetachCalled = false;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		gExt_bExitThread = true;
		gExt_bDllDetachCalled = true;
		break;
	}
	return TRUE;
}
