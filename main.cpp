#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>


std::vector<PROCESSENTRY32> get_processes() {
	std::vector<PROCESSENTRY32> pcs;
	auto ss = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	if (!Process32First(ss, &pe))throw "err";
	do {
		pcs.push_back(pe);
	} while (Process32Next(ss, &pe));
	return pcs;
}

std::vector<MODULEENTRY32> get_modules(DWORD pid) {
	std::vector<MODULEENTRY32> pcs;
	auto ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 pe;
	pe.dwSize = sizeof(pe);
	if (!Module32First(ss, &pe))throw "err";
	do {
		pcs.push_back(pe);
	} while (Module32Next(ss, &pe));
	return pcs;
}
template<typename T>
struct Option {
	T val;
	enum {
		Some,
		None
	} _exists;
	Option(T val) :val(val),_exists(Some){

	};
	Option() :_exists(None){};
	explicit operator bool() const {
		return _exists == Some ? true:false;
	}

	explicit operator T*() const{
		return _exists == Some ? &val : nullptr;
	}

	T get() {
		if (_exists == Some) {
			return val;
		}
		return T();
	}
};

struct Proc {
	DWORD baseAddress;
	DWORD pid;
	DWORD modSize;
	Proc(std::string name) {
		for (const auto & p : get_processes()) {
			if (p.szExeFile == name) {
				pid = p.th32ProcessID;
				break;
			}
		}
		baseAddress=(DWORD)get_modules(pid)[0].modBaseAddr;
		modSize = get_modules(pid)[0].modBaseSize;
	}

	Proc(DWORD pid) : pid(pid), baseAddress((DWORD)get_modules(pid)[0].modBaseAddr),modSize(get_modules(pid)[0].modBaseSize){};
	template<typename T>
	Option<T> rpm(DWORD offset) {
		auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		T buff;
		SIZE_T br;
		ReadProcessMemory(hProc, (LPCVOID)(baseAddress + offset), &buff, sizeof(T), &br);
		return br ? Option<T>(buff) : Option<T>();
	}
	
	std::vector<BYTE> read_some(DWORD offset,DWORD amount) {
		auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		std::vector<BYTE>buff = std::vector<BYTE>(amount);
		SIZE_T br;
		ReadProcessMemory(hProc, (LPCVOID)(baseAddress + offset), &buff[0], amount, &br);
		return buff;
	}


	template<typename T>
	bool wpm(DWORD offset, T val) {
		auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		SIZE_T bw;
		WriteProcessMemory(hProc, baseAddress + offset, val, sizeof(T), &bw);
		return bw ? true : false;
	}


};

int main(){
	__asm NOP;
	__asm NOP;
	__asm NOP;
	__asm NOP;

	__asm NOP;
	__asm NOP;
	__asm NOP;
	__asm NOP;

	__asm NOP;
	__asm NOP;
	__asm NOP;
	__asm NOP;

	__asm NOP;
	__asm NOP;
	__asm NOP;
	__asm NOP;
	volatile int a =5;

	auto p15 =Proc("Project15.exe");
	auto size = p15.baseAddress + p15.modSize;

	auto val = p15.read_some(0, size);
	std::vector<BYTE> nops = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	auto of = std::search(val.begin(), val.end(), nops.begin(), nops.end())-val.begin();
	auto ra = p15.rpm<int>(of + 19).get();
	std::cout << ra;
	std::cin.get();

	return 0;
}