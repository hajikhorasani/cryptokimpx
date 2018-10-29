/* p11-helper.h
 
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


#ifndef P11_HELPER_H
#define P11_HELPER_H

#include <stdlib.h>
#include <stdio.h>
#include <memory>
#include "pkcs11.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef __cplusplus
#include <vector>

//extern "C"
//{
#endif

static std::vector<FILE*> files;
static std::vector<unsigned int> ProcessIDs;
static std::vector<unsigned int> ThreadIDs;
static bool global_isMultiLog;
static bool global_isEnableLog;
static char global_logAddress[FILENAME_MAX];
FILE *printLog(char Address[], unsigned int PId, unsigned int ThId, bool isMultiLog);
int getFilePointerIndex(unsigned int PId,unsigned int ThId);
void SetGlobalSettings(bool log, bool Mlog, char * address);
void p11_log(std::string str, bool simple = false, int seed = -1);
std::string string_format(const std::string fmt_str, ...);
void *loadp11module(const char *name, CK_FUNCTION_LIST_PTR_PTR);
CK_RV unloadp11module(void *module);
void *p11dlopen(const char *filename);
void *p11dlsym(void *handle, const char *symbol);
const char *p11dlerror();
int p11dlclose(void **handle);

typedef void (log_func) (CK_LONG, CK_VOID_PTR, CK_ULONG, CK_VOID_PTR);
typedef struct
{
  CK_ULONG   type;
  const char *name;
} enum_specs;
typedef struct
{
  CK_ULONG type;
  enum_specs *specs;
  CK_ULONG   size;
  const char *name;
} enum_spec;
typedef struct
{
  CK_ULONG          type;
  const char *      name;
  log_func*  	     display;
  void *            arg;
} type_spec;

const char *lookup_enum_spec(enum_spec *spec, CK_ULONG value);
const char *lookup_enum(CK_ULONG type, CK_ULONG value);
void print_enum    (CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_boolean (CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_generic (CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void print_print   (CK_LONG type, CK_VOID_PTR value, CK_ULONG size, CK_VOID_PTR arg);
void show_error    (char *str, CK_RV rc);
void print_ck_info(CK_INFO *info);
void print_slot_list(CK_SLOT_ID_PTR pSlotList, CK_ULONG ulCount);
void print_slot_info(CK_SLOT_INFO *info);
void print_token_info(CK_TOKEN_INFO *info);
void print_mech_list(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG ulMechCount);
void print_mech_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR minfo);
void print_attribute_list(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount);
void print_attribute_list_req(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount);
void print_session_info(CK_SESSION_INFO *info);
enum ck_type {OBJ_T, KEY_T, CRT_T, MEC_T, USR_T, STA_T, RV_T};
extern type_spec ck_attribute_specs[];
extern CK_ULONG ck_attribute_num;
extern enum_spec ck_types[];

#ifdef __cplusplus
//};
#endif

#endif
