#include "loader.hpp"
#include "../includes.hpp"

bool CBaseLoader::Initialize( )
{
	if ( !segmentRawData ) {
		util::console::set_prefix( util::console::ERR );
		util::console::print( "No segment\n" );
		util::console::set_prefix( util::console::NONE );

		return false;
	}

	if ( reinterpret_cast< IMAGE_DOS_HEADER* >( segmentRawData )->e_magic != 0x5A4D ) { /* "MZ" */
		util::console::set_prefix( util::console::ERR );
		util::console::print( "Segment is not injectable\n" );
		util::console::set_prefix( util::console::NONE );

		return false;
	}

	m_ntHeaders = ( PIMAGE_NT_HEADERS ) ( segmentRawData + ( ( PIMAGE_DOS_HEADER ) segmentRawData )->e_lfanew );
	if ( !m_ntHeaders ) {
		util::console::set_prefix( util::console::ERR );
		util::console::print( "STRANGE ERROR m_ntHeaders==nullptr\n" );
		util::console::set_prefix( util::console::NONE );

		return false;
	}

	// Initialize stuff
	//m_LoaderData.m_base = m_ntHeaders->OptionalHeader.ImageBase;
	m_LoaderData.m_size = m_ntHeaders->OptionalHeader.SizeOfImage;
	m_SegmentData.m_size = m_ntHeaders->OptionalHeader.SizeOfHeaders;
	m_SegmentData.m_oep = m_ntHeaders->OptionalHeader.AddressOfEntryPoint;

	// Allocate memory for segment.
	int alloc = reinterpret_cast < int > ( VirtualAlloc( reinterpret_cast < void* > ( m_LoaderData.m_base ) , m_LoaderData.m_size , m_LoaderData.m_type , m_LoaderData.m_protect ) );

	// Verify it.
	if ( alloc == 0x00000000 ) {
		util::console::set_prefix( util::console::ERR );
		util::console::print( "@CBaseLoader::Initialize: Can't allocate virtual memory\n" );
		util::console::set_prefix( util::console::NONE );

		MessageBoxA( NULL , "@CBaseLoader::Initialize: Can't allocate virtual memory" , "ERROR" , MB_OK | MB_ICONERROR );
		std::abort( );
		return false;
	}

	util::console::set_prefix( util::console::NONE );
	util::console::print( "Allocated virtual memory to 0x%p\n" , ( void* ) alloc );

	// Set new global allocation base.
	m_LoaderData.m_base = alloc;

	// Map sections of segment
	this->MapSections( );

	util::console::set_prefix( util::console::NONE );
	util::console::print( "Mapped Sections\n" );

	// Copy segment into new memory & verify it.
	if ( !memcpy( reinterpret_cast < void* > ( alloc ) , segmentRawData , m_SegmentData.m_size ) ) {
		util::console::set_prefix( util::console::ERR );
		util::console::print( "@CBaseLoader::Initialize: Can't copy segment to allocation memory\n" );
		util::console::set_prefix( util::console::NONE );

		MessageBoxA( NULL , "@CBaseLoader::Initialize: Can't copy segment to allocation memory" , "ERROR" , MB_OK | MB_ICONERROR );
		std::abort( );
		return false;
	}

	util::console::set_prefix( util::console::NONE );
	util::console::print( "Copied segment to allocation memory\n" );
	return true;
}

void CBaseLoader::MapSections( )
{
	auto* pSectionHeader = IMAGE_FIRST_SECTION( m_ntHeaders );
	for ( UINT i = 0; i != m_ntHeaders->FileHeader.NumberOfSections; ++i , ++pSectionHeader ) {
		if ( pSectionHeader->SizeOfRawData ) {
			if ( !memcpy( ( ( BYTE* ) m_LoaderData.m_base ) + pSectionHeader->VirtualAddress , segmentRawData + pSectionHeader->PointerToRawData , pSectionHeader->SizeOfRawData ) ) {
				util::console::set_prefix( util::console::ERR );
				util::console::print( "@CBaseLoader::MapSections: Can't map sections: 0x%X\n" , GetLastError( ) );
				util::console::set_prefix( util::console::NONE );

				MessageBoxA( NULL , "@CBaseLoader::MapSections: Can't map sections" , "ERROR" , MB_OK | MB_ICONERROR );
				VirtualFree( ( void* ) m_LoaderData.m_base , 0 , MEM_RELEASE );
				std::abort( );
				return;
			}
		}
	}
}

#define RELOC_FLAG32( RelInfo ) ( ( RelInfo >> 0x0C ) == IMAGE_REL_BASED_HIGHLOW )
#define RELOC_FLAG64( RelInfo ) ( ( RelInfo >> 0x0C ) == IMAGE_REL_BASED_DIR64 )

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void CBaseLoader::InvokeOEP( )
{
	using f_LoadLibraryA = HINSTANCE( WINAPI* )( const char* lpLibFilename );
	using f_GetProcAddress = UINT_PTR( WINAPI* )( HINSTANCE hModule , const char* lpProcName );
	using f_DLL_ENTRY_POINT = BOOL( WINAPI* )( void* hDll , DWORD dwReason , void* pReserved );

	BYTE* pBase = reinterpret_cast< BYTE* >( m_LoaderData.m_base );
	PIMAGE_NT_HEADERS pNtHeader = ( PIMAGE_NT_HEADERS ) ( pBase + ( ( PIMAGE_DOS_HEADER ) pBase )->e_lfanew );
	auto* pOpt = &pNtHeader->OptionalHeader;

	auto _LoadLibraryA = ( f_LoadLibraryA ) GetProcAddress( GetModuleHandleA( "kernel32.dll" ) , "LoadLibraryA" );
	auto _GetProcAddress = reinterpret_cast< f_GetProcAddress >( GetProcAddress );
	auto _DllMain = reinterpret_cast< f_DLL_ENTRY_POINT >( pBase + pOpt->AddressOfEntryPoint );

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if ( LocationDelta ) {
		if ( !pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size ) {
			return;
		}

		auto* pRelocData = reinterpret_cast< IMAGE_BASE_RELOCATION* >( pBase + pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress );
		while ( pRelocData->VirtualAddress ) {
			UINT AmountOfEntries = ( pRelocData->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
			WORD* pRelativeInfo = reinterpret_cast< WORD* >( pRelocData + 1 );
			for ( UINT i = 0; i != AmountOfEntries; i++ , ++pRelativeInfo ) {
				if ( RELOC_FLAG( *pRelativeInfo ) ) {
					UINT_PTR* pPatch = reinterpret_cast< UINT_PTR* >( pBase + pRelocData->VirtualAddress + ( ( *pRelativeInfo ) & 0xFFF ) );
					*pPatch += reinterpret_cast< UINT_PTR >( LocationDelta );
				}
			}
			pRelocData = reinterpret_cast< IMAGE_BASE_RELOCATION* >( reinterpret_cast< BYTE* >( pRelocData ) + pRelocData->SizeOfBlock );
		}
	}

	if ( pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size ) {
		auto* pImportDescr = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( pBase + pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
		while ( pImportDescr->Name ) {
			char* szMod = reinterpret_cast< char* >( pBase + pImportDescr->Name );
			HINSTANCE hDll = _LoadLibraryA( szMod );

			ULONG_PTR* pThunkRef = reinterpret_cast< ULONG_PTR* >( pBase + pImportDescr->OriginalFirstThunk );
			ULONG_PTR* pFuncRef = reinterpret_cast< ULONG_PTR* >( pBase + pImportDescr->FirstThunk );

			if ( !pThunkRef )
				pThunkRef = pFuncRef;

			for ( ; *pThunkRef; ++pThunkRef , ++pFuncRef ) {
				if ( IMAGE_SNAP_BY_ORDINAL( *pThunkRef ) ) {
					*pFuncRef = _GetProcAddress( hDll , reinterpret_cast< char* >( *pThunkRef & 0xFFFF ) );
				}
				else {
					auto* pImport = reinterpret_cast< IMAGE_IMPORT_BY_NAME* >( pBase + ( *pThunkRef ) );
					*pFuncRef = _GetProcAddress( hDll , pImport->Name );
				}
			}
			++pImportDescr;
		}
	}

	if ( pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_TLS ].Size ) {
		auto* pTLS = reinterpret_cast< IMAGE_TLS_DIRECTORY* >( pBase + pOpt->DataDirectory [ IMAGE_DIRECTORY_ENTRY_TLS ].VirtualAddress );
		auto* pCallback = reinterpret_cast< PIMAGE_TLS_CALLBACK* >( pTLS->AddressOfCallBacks );
		for ( ; pCallback && *pCallback; ++pCallback ) {
			( *pCallback )( pBase , DLL_PROCESS_ATTACH , nullptr );
		}
	}

	util::console::set_prefix( util::console::NONE );
	util::console::print( "CallbackBeforeOEP\n" );
	this->CallbackBeforeOEP( );

#if 1
	util::console::set_prefix( util::console::NONE );
	util::console::print( "Invoking OEP\n" );
	_DllMain( pBase , DLL_PROCESS_ATTACH , nullptr );

	util::console::set_prefix( util::console::NONE );
	util::console::print( "CallbackAfterOEP\n" );
	this->CallbackAfterOEP( );
#else
	__debugbreak( );
#endif
}
