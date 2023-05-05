#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include "kinterface.h"
#include "utils.h"
#include "mmap.h"
 // PRESENT INJECTOR BY TupleDev //
void main( )
{
//const auto pid = utils::get_process_id( "1.exe" );
auto hwnd = FindWindowW(L"DagorWClass", 0);
DWORD pid = NULL;
DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
//	const auto pid = utils::get_process_id( "notepad.exe" );


	if ( pid )
	{
		printf( "game found %i\n", pid );

		kinterface->initialize( );
		auto cur_path = std::filesystem::current_path();
		cur_path += "\\CRSED.dll";

		mmap->map( pid, utils::read_file(cur_path.c_str()).data( ) );
	}
	else
	{
		printf( "game not found\n" );
	}

	kinterface->unload( );

	std::cin.get( );
}
