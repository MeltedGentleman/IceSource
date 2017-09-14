#define _CRT_SECURE_NO_WARNINGS
//#define _WIN32_WINNT _WIN32_WINNT_WINXP
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN 

#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <iterator>
#include <vector>
#include <fstream>
#include <sstream>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinINet.h>
#include <algorithm>
#include <random>
#include <ostream>
#include <chrono>
#include <typeinfo>
#include <fcntl.h>
#include <io.h>
#include <urlmon.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <typeinfo>
#include <WinInet.h>
#include <fstream>
#include <algorithm>
#include <Psapi.h>
#include <tlhelp32.h>
#include <math.h>
#include <cmath>
#include <Windows.h>
#include <iostream>
#include <string> 
#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <istream>
#include <iterator>
#include <algorithm>
#include <string>
#include <Psapi.h>
#include <tlhelp32.h>
#include <Windows.h>
#include <assert.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <conio.h>
#include <time.h>
#include <map>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "wininet")

#include "stdafx.h"

#include "Scan.h"
#include "Main.h"
//#include "Functions.h"

#pragma once

typedef int(RLUAState);
typedef int(PMSGTYPE);

#define ERRMSG		3
#define WARNMSG		2
#define INFOMSG		1
#define NORMMSG		0

#define LUA_GLOBALSINDEX -10002
#define LUA_REGISTRYINDEX -10000

#define rlua_getglobal(l,g)			 Rlua::rlua_getfield(l, LUA_GLOBALSINDEX, g)
#define rlua_pushbool(luaState, boolean)     int property = *(DWORD *)(luaState + 16); *(DWORD*)property = boolean; *(DWORD *)(property + 8) = 3; *(DWORD *)(luaState + 16) += 16;
#define rlua_pushnil(a1)             *(DWORD *)(*(DWORD *)(a1 + 16) + 8) = 0; *(DWORD *)(a1 + 16) += 16
#define rlua_tostring(l,idx)		 Rlua::rlua_toLstring(l, (idx), 0)
#define rlua_pop(L,n)                Rlua::rlua_settop(L, -(n)-1)
#define rlua_isnil(L,n)			     (Rlua::rlua_type(L, (n), TRUE) == 0)
#define RLUA_TNONE					 (-1)
#define RLUA_TNIL                     0
#define RLUA_TNUMBER                  2
#define RLUA_TBOOLEAN                 3
#define RLUA_TSTRING                  4
#define RLUA_TLIGHTUSERDATA		      1
#define RLUA_TTABLE                   7
#define RLUA_TUSERDATA			      8
#define RLUA_TFUNCTION				  6
#define RLUA_TPROTO                   9
#define RLUA_TTHREAD                  5
#define RLUA_TUPVALUE                 10

namespace Retcheck {
	DWORD unprotect(DWORD addr)
	{
		BYTE* tAddr = (BYTE *)addr;

		do {
			tAddr += 0x10;
		} while (!(tAddr[0] == 0x55 && tAddr[1] == 0x8B && tAddr[2] == 0xEC));

		DWORD funcSz = tAddr - (BYTE*)addr;

		PVOID nFunc = VirtualAlloc(NULL, funcSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (nFunc == NULL)
			return addr;

		memcpy(nFunc, (void*)addr, funcSz);

		DWORD pos = (DWORD)nFunc;
		BOOL valid = false;
		do {
			if (*(BYTE*)pos == 0x72 && *(BYTE*)(pos + 0x2) == 0xA1 && (*(BYTE*)(pos + 0x7)) == 0x8B) {
				memcpy((void*)pos, "\xEB", 1);

				DWORD cNFunc = (DWORD)nFunc;
				do {
					if (*(BYTE*)cNFunc == 0xE8)
					{
						DWORD tFunc = addr + (cNFunc - (DWORD)nFunc);
						DWORD oFunc = (tFunc + *(DWORD*)(tFunc + 1)) + 5;

						if (oFunc % 16 == 0)
						{
							DWORD realCAddr = oFunc - cNFunc - 5;
							*(DWORD*)(cNFunc + 1) = realCAddr;
						}
						cNFunc += 5;
					}
					else
						cNFunc += 1;
				} while (cNFunc - (DWORD)nFunc < funcSz);

				valid = true;
			}
			pos += 1;
		} while (pos < (DWORD)nFunc + funcSz);

		if (!valid) {
			VirtualFree(nFunc, funcSz, MEM_RELEASE);
			return addr;
		}

		return (DWORD)nFunc;
	}
}

namespace Rlua {
	typedef void(__cdecl *Lua_getfield)(RLUAState lst, int index, const char *k);
	Lua_getfield rlua_getfield = (Lua_getfield)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x6A\x01\xFF\x75\x10", "xxxxxxxx"));

	typedef void(__cdecl *Lua_settop)(RLUAState lst, int index);
	Lua_settop rlua_settop = (Lua_settop)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x8B\x55\x0C\x85\xD2\x78\x38", "xxxxxxxxxx"));

	typedef void(__cdecl *Lua_pushstring)(RLUAState lst, const char *s);
	Lua_pushstring rlua_pushstring = (Lua_pushstring)aobscan::scan("\x55\x8B\xEC\x8B\x55\x0C\x85\xD2\x75\x0D", "xxxxxxxxxx");

	//typedef void(__cdecl *RLua_pushlstring)(RLUAState lst, const char *s, size_t length);
	//RLua_pushlstring rlua_pushlstring = (RLua_pushlstring)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x57\x8B\x7D\x08\x8B\x4F\x08\x8B\x44\x39\x60\x3B\x44\x39\x54\x72\x09\x57\xE8\x00\x00\x00\x00\x83\xC4\x04\x56\xFF\x75\x10\x8B\x77\x10\xFF\x75\x0C\x57\xE8\x00\x00\x00\x00\x89\x06\xC7\x46\x00\x00\x00\x00\x00\x83\x47\x10\x10\xA1\x00\x00\x00\x00\x8B\x4D\x04\x83\xC4\x0C\x2B\xC8\x5E\x3B\x0D\x00\x00\x00\x00\x72\x39\xA1\x00\x00\x00\x00\x8B\x4D\x04\x2B\xC8\x3B\x0D\x00\x00\x00\x00\x72\x27\xA1\x00\x00\x00\x00\x81\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x57\xA3\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x04\x5F\x5D\xC3", "xxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxx????xxxx?????xxxxx????xxxxxxxxxxx????xxx????xxxxxxx????xxx????xx????????xx????xx????????x????xxxxxx"));

	typedef void(__cdecl *Lua_pushvalue)(RLUAState lst, int index);
	Lua_pushvalue rlua_pushvalue = (Lua_pushvalue)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\xFF\x75\x0C\x8B\x75\x08\x56\xE8\x00\x00\x00\x00\x8B\x56\x0C\x83\xC4\x08", "xxxxxxxxxxxx????xxxxxx"));

	typedef int(__cdecl *Lua_pcall)(RLUAState lst, int nargs, int nresults, int errfunc);
	Lua_pcall rlua_pcall = (Lua_pcall)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x8B\x45\x14\x83\xEC\x08\x57", "xxxxxxxxxx"));

	typedef void(__cdecl *Lua_setfield)(RLUAState lst, int index, const char *k);
	Lua_setfield rlua_setfield = (Lua_setfield)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x83\xEC\x10\x53\x56\x8B\x75\x08\x57\xFF\x75\x0C\x56\xE8\x00\x00\x00\x00\x8B\x55\x10\x83\xC4\x08\x8B\xCA\x8B\xF8\x8D\x59\x01\x8A\x01\x41\x84\xC0\x75\xF9\x2B\xCB\x51\x52\x56\xE8\x00\x00\x00\x00\x89\x45\xF0", "xxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxx????xxx"));

	typedef void(__cdecl *Lua_pushnumber)(RLUAState lst, double n);
	Lua_pushnumber rlua_pushnumber = (Lua_pushnumber)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x8B\x4D\x08\x0F\x28\x15", "xxxxxxxxx"));

	typedef void(__cdecl *Lua_pushcclosure)(RLUAState state, int func, int idx);
	//Lua_pushcclosure rlua_pushcclosure = (Lua_pushcclosure)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x53\x56\x8B\x75\x08\x8B\x46\x1C", "xxxxxxxxxxx"));
	//Lua_pushcclosure rlua_pushcclosure = (Lua_pushcclosure)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\x8B\x4E\x08\x8B\x44\x0E\x60", "xxxxxxxxxxxxxx"));

	typedef const char*(__cdecl *Lua_ToLString)(RLUAState lst, int idx, size_t *len);
	Lua_ToLString rlua_toLstring = (Lua_ToLString)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\xB9\x00\x00\x00\x00\x66\xFF\x46\x34", "xxxxxxxx????xxxx"));

	typedef bool(__cdecl *Lua_toBoolean)(RLUAState lst, int idx);
	Lua_toBoolean rlua_toBool = (Lua_toBoolean)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\xFF\x75\x0C\xFF\x75\x08\xE8\x00\x00\x00\x00\x83\xC4\x08\x8B\x48\x08\x85\xC9", "xxxxxxxxxx????xxxxxxxx"));

	typedef int(__cdecl *Lua_tonumber)(RLUAState lst, int idx);
	Lua_tonumber rlua_tonumber = (Lua_tonumber)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x83\xEC\x10\xFF\x75\x0C\xFF\x75\x08\xE8", "xxxxxxxxxxxxx"));

	typedef void*(__cdecl *Lua_touserdata)(RLUAState lst, int a1);
	//Lua_touserdata rlua_touserdata = (Lua_touserdata)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\xFF\x75\x0C\xFF\x75\x08\xE8\x00\x00\x00\x00\x8B\x48\x08\x83\xC4\x08\x49", "xxxxxxxxxx????xxxxxxx"));

	typedef void*(__cdecl *Lua_newuserdata)(RLUAState lst, int a1);
	//Lua_newuserdata rlua_newuserdata = (Lua_newuserdata)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\x57\x8B\x4E\x08\x8B\x44\x31\x60\x3B\x44\x31\x54\x72\x09\x56\xE8\x00\x00\x00\x00\x83\xC4\x04\x8B\x46\x0C", "xxxxxxxxxxxxxxxxxxxxxxx????xxxxxx"));

	typedef int(__cdecl *Lua_newthread)(RLUAState lst);
	//Lua_newthread rlua_newthread = (Lua_newthread)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x51\x56\x8B\x75\x08\x57\x8B\x4E\x08", "xxxxxx????xx????xxxx????xxxxxxxxx"));

	typedef void*(__cdecl *Lua_setmetatable)(RLUAState lst, int idx);
	// rlua_setmetatable = (Lua_setmetatable)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x53\x56\x57\xFF\x75\x0C\x8B\x7D\x08", "xxxxxxxxxxxx"));

	typedef void(__cdecl *Lua_getmetatable)(RLUAState lst, int idx);
	//Lua_getmetatable rlua_getmetatable = (Lua_getmetatable)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x57\xFF\x75\x0C\x8B\x7D\x08\x57\xE8\x00\x00\x00\x00\x83\xC4\x08", "xxxxxxxxxxxxx????xxx"));

	typedef int(__cdecl *Lua_getmetafield)(RLUAState lst, int idx, const char* e);
	//	Lua_getmetafield rlua_getmetafield = (Lua_getmetafield)aobscan::scan("\x55\x8B\xEC\x56\xFF\x75\x0C\x8B\x75\x08\x56\xE8\x00\x00\x00\x00\x83\xC4\x08\x85\xC0\x74\x57", "xxxxxxxxxxxx????xxxxxxx");

	typedef int(__cdecl *Lua_type)(RLUAState lst, int idx, bool type);
	Lua_type rlua_type = (Lua_type)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\xFF\x75\x0C\xFF\x75\x08\xE8\x00\x00\x00\x00\x83\xC4\x08\x3D\x00\x00\x00\x00\x75\x05", "xxxxxxxxxx????xxxx????xx"));

	typedef int(__cdecl *Lua_replace)(RLUAState lst, int idx);
	//Lua_replace rlua_replace = (Lua_replace)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\x57\x8B\x7D\x0C\x81\xFF", "xxxxxxxxxxxxx"));

	typedef int(__cdecl *Lua_rawgeti)(RLUAState lst, int idx, int a3);
	//Lua_rawgeti rlua_rawgeti = (Lua_rawgeti)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\xFF\x75\x0C\x8B\x75\x08\x56\xE8\x00\x00\x00\x00\xFF\x75\x10", "xxxxxxxxxxxx????xxx"));

	typedef int(__cdecl *Lua_objlen)(RLUAState lst, int idx);
	//Lua_objlen rlua_objlen = (Lua_objlen)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x57\xFF\x75\x0C\x8B\x7D\x08\x57\xE8\x00\x00\x00\x00\x8B\xF0", "xxxxxxxxxxxxx????xx"));

	typedef int(__cdecl *Lua_next)(RLUAState lst, int idx);
	Lua_next rlua_next = (Lua_next)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x83\xEC\x18\x56\x8B\x75\x08\x57\xFF\x75\x0C", "xxxxxxxxxxxxxx"));

	typedef int(__cdecl *Lua_ref)(RLUAState lst, int idx);
	//Lua_ref rlua_ref = (Lua_ref)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\x57\x8B\x7D\x0C\x8D\x87\x00\x00\x00\x00\x3D\x00\x00\x00\x00\x77\x0C\x8B\x46\x10\x2B\x46\x1C\x47\xC1\xF8\x04\x03\xF8\x8B\x46\x10", "xxxxxxxxxxxxx????x????xxxxxxxxxxxxxxxxx"));

	typedef int(__cdecl *Lua_pushlightuserdata)(RLUAState lst, int idx);
	//Lua_pushlightuserdata rlua_pushlightuserdata = (Lua_pushlightuserdata)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x8B\x55\x08\x8B\x45\x0C\x8B\x4A\x10", "xxxxxxxxxxxx"));

	typedef int*(__cdecl *Lua_topointer)(RLUAState state, int idx);
	//Lua_topointer rlua_topointer = (Lua_topointer)aobscan::scan("\x55\x8B\xEC\xFF\x75\x0C\xFF\x75\x08\xE8\x00\x00\x00\x00\x8B\x48\x08\x49", "xxxxxxxxxx????xxxx");

	typedef int(__cdecl *Lua_tonumber)(RLUAState lst, int a2);
	//Lua_tonumber rlua_tonumber = (Lua_tonumber)aobscan::scan("\x55\x8B\xEC\x83\xEC\x10\xFF\x75\x0C\xFF\x75\x08", "xxxxxxxxxxxx");

	typedef int*(__cdecl *Lua_newtable)(RLUAState lst, int a1, int a2);
	//Lua_newtable rlua_createtable = (Lua_newtable)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x57\x8B\x7D\x08\x8B\x4F\x08\x8B\x44\x39\x60\x3B\x44\x39\x54\x72\x09\x57\xE8\x00\x00\x00\x00\x83\xC4\x04\x56\xFF\x75\x10\x8B\x77\x10\xFF\x75\x0C\x57\xE8\x00\x00\x00\x00\x89\x06\xC7\x46\x00\x00\x00\x00\x00\x83\x47\x10\x10\xA1\x00\x00\x00\x00\x8B\x4D\x04\x83\xC4\x0C\x2B\xC8\x5E\x3B\x0D\x00\x00\x00\x00\x72\x39\xA1\x00\x00\x00\x00\x8B\x4D\x04\x2B\xC8\x3B\x0D\x00\x00\x00\x00\x72\x27\xA1\x00\x00\x00\x00\x81\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x57\xA3\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x83\xC4\x04\x5F\x5D\xC3", "xxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxx????xxxx?????xxxxx????xxxxxxxxxxx????xxx????xxxxxxx????xxx????xx????????xx????xx????????x????xxxxxx"));

	typedef int*(__cdecl *Lua_settable)(RLUAState lst, int a2);
	//Lua_settable rlua_settable = (Lua_settable)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\xFF\x75\x0C\x8B\x75\x08\x56\xE8\x00\x00\x00\x00\x8B\x56\x10", "xxxxxxxxxxxx????xxx"));

	typedef void*(__cdecl *Lua_pushinteger)(RLUAState lst, int a2);
	//Lua_pushinteger rlua_pushinteger = (Lua_pushinteger)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x66\x0F\x6E\x4D\x00\x8B\x55\x08", "xxxxxxx?xxx"));

	typedef void*(__cdecl *Lua_pushthread)(RLUAState lst, int thread);
	//Lua_pushthread rlua_pushthread = (Lua_pushthread)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x08\x8B\x46\x10", "xxxxxxxxxx"));

	typedef int(__cdecl *Lua_tointeger)(RLUAState lst, int idx);
	//Lua_tointeger rlua_tointeger = (Lua_tointeger)aobscan::scan("\x55\x8B\xEC\x83\xEC\x18\xFF\x75\x0C\xFF\x75\x08", "xxxxxxxxxxxx");

	typedef void*(__cdecl *Lua_concat)(RLUAState lst, int idx);
	//Lua_concat rlua_concat = (Lua_concat)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x8B\x75\x0C\x57\x8B\x7D\x08\x83\xFE\x02", "xxxxxxxxxxxxxx"));

	typedef void*(__cdecl *Lua_typerror)(RLUAState lst, int idx);
	//Lua_typerror rlua_typerror = (Lua_typerror)aobscan::scan("\x55\x8B\xEC\x56\xFF\x75\x0C\x8B\x75\x08\x56\xE8\x00\x00\x00\x00\x50", "xxxxxxxxxxxx????x");

	typedef void*(__cdecl *Lua_insert)(RLUAState lst, int idx);
	//Lua_insert rlua_insert = (Lua_insert)Retcheck::unprotect(aobscan::scan("\x55\x8B\xEC\x56\x57\xFF\x75\x0C\x8B\x7D\x08\x57\xE8\x00\x00\x00\x00\x8B\x57\x10", "xxxxxxxxxxxxx????xxx"));

	typedef int(__thiscall *GlOpen)(int a1, int a2);
	//GlOpen GlobalStateOpen = (GlOpen)aobscan::scan("\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x4C\x53\x56\x8B\xD9\x57\x89\x5D\xE0", "xxxxxx????xx????xxxx????xxxxxxxxxxx");

	typedef int(__thiscall *OState)(int a1);
	//OState OpenState = (OState)aobscan::scan("\x55\x8B\xEC\xA1\x00\x00\x00\x00\x85\xC0\x75\x05\xE8\x00\x00\x00\x00\xFF\x75\x08\x8B\xC8\xE8\x00\x00\x00\x00\x5D\xC3", "xxxx????xxxxx????xxxxxx????xx");

	int rlua_gettop(RLUAState state) {
		return (*(DWORD *)(state + 16) - *(DWORD *)(state + 28)) >> 4;
	}

}

void rlua_print(PMSGTYPE out, const char * msgfmt, ...)
{
	va_list args;
	va_start(args, msgfmt);
	char buff[1024];
	vsnprintf_s(buff, sizeof(buff), msgfmt, args);
	((int(*)(int, int, const char*, ...))aobscan::scan("\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x30\x8D\x45\x14", "xxxxxx????xx????xxxx????xxxxxx"))(((int(__cdecl*)())aobscan::scan("\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x51\x64\xA1\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\x8B\x0C\x88\xA1\x00\x00\x00\x00\x3B\x81\x00\x00\x00\x00\x7E\x4F", "xxxxxx????xx????xxxx????xxx????xx????xxxx????xx????xx"))(), out, buff);
	va_end(args);
}