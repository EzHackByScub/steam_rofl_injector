class mmap_t
{
private:



	typedef struct _remote_dll {
		INT status;
		uintptr_t dll_main_address;
		HINSTANCE dll_base;
	} remote_dll, *premote_dll;

	auto get_nt_headers( const std::uintptr_t image_base ) -> IMAGE_NT_HEADERS *
	{
		if (image_base == 0)
		{
			printf("can't find dll;");

			Sleep(-1);


		}
		const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER * > ( image_base );

		return reinterpret_cast< IMAGE_NT_HEADERS * > ( image_base + dos_header->e_lfanew );
	}

	auto rva_va( const std::uintptr_t rva, IMAGE_NT_HEADERS *nt_header, void *local_image ) -> void *
	{
		const auto first_section = IMAGE_FIRST_SECTION( nt_header );

		for ( auto section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++ )
		{
			if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize )
			{
				return ( unsigned char * )local_image + section->PointerToRawData + ( rva - section->VirtualAddress );
			}
		}

		return 0;
	}

	auto relocate_image( void *remote_image, void *local_image, IMAGE_NT_HEADERS *nt_header ) -> bool
	{
		typedef struct _RELOC_ENTRY
		{
			ULONG ToRVA;
			ULONG Size;
			struct
			{
				WORD Offset : 12;
				WORD Type : 4;
			} Item[1];
		} RELOC_ENTRY, *PRELOC_ENTRY;

		const auto delta_offset = ( std::uintptr_t )remote_image - nt_header->OptionalHeader.ImageBase;

		if ( !delta_offset )
		{
			return true;
		}

		else if ( !( nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) )
		{
			return false;
		}

		auto relocation_entry = ( RELOC_ENTRY * )rva_va( nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, local_image );
		const auto relocation_end = ( std::uintptr_t )relocation_entry + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if ( relocation_entry == nullptr )
		{
			return true;
		}

		while ( ( std::uintptr_t )relocation_entry < relocation_end && relocation_entry->Size )
		{
			auto records_count = ( relocation_entry->Size - 8 ) >> 1;

			for ( auto i = 0ul; i < records_count; i++ )
			{
				WORD fixed_type = ( relocation_entry->Item[i].Type );
				WORD shift_delta = ( relocation_entry->Item[i].Offset ) % 4096;

				if ( fixed_type == IMAGE_REL_BASED_ABSOLUTE )
				{
					continue;
				}

				if ( fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64 )
				{
					auto fixed_va = ( std::uintptr_t )rva_va( relocation_entry->ToRVA, nt_header, local_image );

					if ( !fixed_va )
					{
						fixed_va = ( std::uintptr_t )local_image;
					}

					*( std::uintptr_t * )( fixed_va + shift_delta ) += delta_offset;
				}
			}

			relocation_entry = ( PRELOC_ENTRY )( ( LPBYTE )relocation_entry + relocation_entry->Size );
		}

		return true;
	}

	auto resolve_function_address( LPCSTR module_name, LPCSTR function_name ) -> std::uintptr_t
	{
		const auto handle = LoadLibraryExA( module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES );

		const auto offset = ( std::uintptr_t )GetProcAddress( handle, function_name ) - ( std::uintptr_t )handle;

		FreeLibrary( handle );

		return offset;
	}

	auto write_sections( int pid, void *module_base, void *local_image, IMAGE_NT_HEADERS *nt_header ) -> void
	{
		auto section = IMAGE_FIRST_SECTION( nt_header );

		for ( WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++ )
		{
			if (!kinterface->write_virtual_memory(pid, (std::uintptr_t)((std::uintptr_t)module_base + section->VirtualAddress), (void*)((std::uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData))
			{
				printf("mapping failed, unlucky :< Please Restart Your pc and try againg.");
				Sleep(-1);

			}
			}
	}



public:

	auto map( const int pid, void *buffer ) -> bool
	{
		const auto nt_header = get_nt_headers( reinterpret_cast< std::uintptr_t > ( buffer ) );
		printf( "nt_headers: 0x%llx\n", nt_header );

		std::uintptr_t mdl = 0;
		const auto remote_user32_base = kinterface->get_module_base( pid, "user32.dll");
		if (!remote_user32_base)
		{
			printf("can't get a remote modulebase. Please map the driver\n");
			return false;
		}
		printf("user32 %p \n", remote_user32_base);
		auto user32local = 	LoadLibraryW(L"USER32.DLL");
		if (!user32local)
		{
			printf("can't load user32.dll\n");
			return false;
		}

		auto hooked_proc = GetProcAddress(user32local, "GetKeyState"); // USER32.GetKeyboardState 
		if (!hooked_proc)
		{
			printf("can't find procedure\n");
			return false;
		}
		auto proc_offset =  (uint64_t)hooked_proc - (uint64_t)user32local;
		auto remote_proc = remote_user32_base + proc_offset;

		printf("remote proc %p\n", remote_proc);
		unsigned char is_hooked = kinterface->read_virtual_memory<unsigned char>(pid, remote_proc);

			if (is_hooked != 0xe9)
			{
				printf("target function isnt hooked\n");
				return false;
			}
	
		signed int jmp_dst = kinterface->read_virtual_memory<unsigned int>(pid, remote_proc+1);
		uint64_t hook_buffer = remote_proc + jmp_dst + 5;
		uint64_t exec_point = hook_buffer - 5 - 6; // -6
		printf("buffer at %p\n", hook_buffer);
		printf("exec_point at %p\n", exec_point);
		auto region_base = hook_buffer & ~0xfff;
	//	auto code_base = region_base+0x1000;
		printf("region_base %p\n", region_base);
	//	printf("code_base %p\n", code_base);
		constexpr int buffer_size = 0xf000 + /*header*/  0x1000  ;
		if (nt_header->OptionalHeader.SizeOfImage > buffer_size)
		{
			printf("dll to big :< 64kb is maximum\n");
			return false;
		}

		
		if (!relocate_image((void*)region_base, buffer, nt_header))
		{
			printf("[!] /FIXEDBASE ? \n");
		//	return false;
		}
		auto remote_entrypoint = region_base + nt_header->OptionalHeader.AddressOfEntryPoint;
		printf("remote_entrypoint %p\n", remote_entrypoint);


		 //   7FF9ACAD0590 - 48 B8 40534883EC20E90B - mov rax, 0BE920EC83485340 original_code
			//7FF9ACAD059A - 48 A3 8005ADACF97F0000 - mov[7FF9ACAD0580], rax
			//7FF9ACAD05A4 - E9 BAFFFFFF - jmp 7FF9ACAD0563 entrypoint
		// A348
	 auto original_code = 	kinterface->read_virtual_memory<__int64>(pid, exec_point);

#pragma pack(push, 1)
	 __declspec(align(1)) struct  call_entry_code
	 {
		 __declspec(align(1)) unsigned	 __int16 movraxabsval = 0xB848;
		 __declspec(align(1))	 unsigned __int64 valuetomov = 0;
		 __declspec(align(1))	 unsigned __int16 movraxtomemory = '\x48\xA3';
		 __declspec(align(1)) unsigned	 __int64 addresstomov = 0;
		 __declspec(align(1)) unsigned	 char call_entry_point = 0xe9;
		 __declspec(align(1)) unsigned	 int entry_point_offset = 0;
		// __declspec(align(1)) unsigned	 char ret = 0xc3;
	 }call_code;
#pragma pack(pop)
	
	 auto shell_code_base =   exec_point + 0x1a;
	 auto call_entry_point_RIP= shell_code_base + offsetof(call_entry_code, call_entry_point);
	 call_code.entry_point_offset = remote_entrypoint - call_entry_point_RIP-5;
	  // 0x1A
	 call_code.valuetomov = original_code;
	 call_code.addresstomov = exec_point;

	    kinterface->write_virtual_memory(pid, shell_code_base, &call_code, sizeof(call_entry_code));
		write_sections(pid, (void*)region_base, buffer, nt_header);
		kinterface->write_virtual_memory<__int16>(pid, exec_point, 0x18EB); //call entrypoint
	
	

		return true;
	}
};

static mmap_t *mmap = new mmap_t( );