#pragma once
#include <windows.h>
#include "../util/address/address.hpp"

struct SegmentData_t {
	// Size of segment. (For memcpy)
	int m_size;

	// RVA to OriginalEntryPoint.
	int m_oep;
};

struct LoaderData_t
{
	// Allocation base address.
	int m_base = 0x0;

	// Allocation size. (Must be bigger than segment size)
	int m_size;

	// Allocation type.
	int m_type = MEM_COMMIT | MEM_RESERVE;

	// Page protect type.
	int m_protect = PAGE_EXECUTE_READWRITE;
};

class CBaseLoader {
public:
	bool Initialize( );
	void MapSections( );

	virtual void CallbackBeforeOEP( ) { };
	virtual void CallbackAfterOEP( ) { };

	void InvokeOEP( );

	util::address GetBase( ) {
		if ( !m_LoaderData.m_base )
			return util::address( 0U );

		return util::address( ( void* ) m_LoaderData.m_base );
	}

	PIMAGE_NT_HEADERS m_ntHeaders = nullptr;
	SegmentData_t m_SegmentData = { 0x0 , 0x0 };
	LoaderData_t m_LoaderData = { 0x0 , 0x0 , MEM_COMMIT | MEM_RESERVE , PAGE_EXECUTE_READWRITE };
};