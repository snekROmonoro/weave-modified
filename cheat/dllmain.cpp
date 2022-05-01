#include "includes.hpp"
#include <stdexcept>

bool hooked_everything = false;

IDirect3DDevice9* g_pD3dDevice = nullptr;

std::vector< util::modules::Module > g_vecCsgoModules;

// Simple helper function to load an image into a DX9 texture with common settings
bool LoadTextureFromFile( const char* filename , PDIRECT3DTEXTURE9* out_texture , int* out_width , int* out_height )
{
	// Load texture from disk
	PDIRECT3DTEXTURE9 texture;
	HRESULT hr = D3DXCreateTextureFromFileA( g_pD3dDevice , filename , &texture );
	if ( hr != S_OK )
		return false;

	// Retrieve description of the texture surface so we can access its size
	D3DSURFACE_DESC my_image_desc;
	texture->GetLevelDesc( 0 , &my_image_desc );
	*out_texture = texture;
	if ( out_width )
		*out_width = ( int ) my_image_desc.Width;

	if ( out_height )
		*out_height = ( int ) my_image_desc.Height;
	return true;
}

// Simple helper function to load an image into a DX9 texture with common settings
bool LoadTextureFromMemory( void* pSrcData , UINT SrcDataSize , PDIRECT3DTEXTURE9* out_texture , int* out_width , int* out_height ) {
	PDIRECT3DTEXTURE9 texture;
	HRESULT hr = D3DXCreateTextureFromFileInMemory( g_pD3dDevice , pSrcData , SrcDataSize , &texture );
	if ( hr != S_OK )
		return false;

	// Retrieve description of the texture surface so we can access its size
	D3DSURFACE_DESC my_image_desc;
	texture->GetLevelDesc( 0 , &my_image_desc );
	*out_texture = texture;
	if ( out_width )
		*out_width = ( int ) my_image_desc.Width;

	if ( out_height )
		*out_height = ( int ) my_image_desc.Height;
	return true;
}

#define REG void* ecx, void* edx
#define REG_OUT ecx, edx

typedef void* ( *CreateInterfaceFn )( const char* pName , int* pReturnCode );

template<typename T>
T* GetInterface( const char* szModuleName , const char* szInterfaceVersion )
{
	CreateInterfaceFn f = reinterpret_cast< CreateInterfaceFn >( GetProcAddress( GetModuleHandleA( szModuleName ) , "CreateInterface" ) );
	auto result = reinterpret_cast< T* >( f( szInterfaceVersion , nullptr ) );

	if ( !result ) {
		throw std::runtime_error( std::string( "[GetInterface] Failed to GetOffset interface: " ) + szInterfaceVersion );
	}

	return result;
}

int _stdcall init( uintptr_t mod )
{
	if ( !util::console::initialize_console( "DEBUG" ) ) {
		MessageBoxA( NULL , "couldn't initialize console" , "DEBUG" , MB_OK | MB_ICONERROR );
		FreeLibraryAndExitThread( HMODULE( mod ) , 0 );
		return EXIT_SUCCESS;
	}

	while ( !GetModuleHandleA( "serverbrowser.dll" ) )
		std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );

	try {

		// dump modules ptr
		{
			if ( util::modules::GetAllModules( g_vecCsgoModules ) ) {
				/*
				util::console::set_prefix( util::console::WARN );
				for ( auto& mod : g_vecCsgoModules )
				{
					util::console::print( "module: %s = 0x%p\n" , mod.GetName( ).data( ) , mod.GetBase( ).get< void* >( ) );
				}
				util::console::set_prefix( util::console::NONE );
				*/
			}
			else {
				util::console::set_prefix( util::console::ERR );
				util::console::print( "failed to dump modules\n" );
				util::console::set_prefix( util::console::NONE );
				throw std::runtime_error( "failed to dump modules" );
			}
		}

		g_pD3dDevice = util::pattern::search( "shaderapidx9.dll" , "A1 ? ? ? ? 50 8B 08 FF 51 0C" , true ).add( 1 ).deref( ).deref( ).get< IDirect3DDevice9* >( );
		if ( !g_pD3dDevice ) {
			throw std::runtime_error( "failed to get g_pD3dDevice" );
		}

		MH_STATUS initialize_status = MH_Initialize( );
		if ( initialize_status != MH_OK ) {
			throw std::runtime_error( std::string( "failed to initialize MinHook, status: " ) + MH_StatusToString( initialize_status ) );
		}

		// Load Settings
		g_Settings.Load( );

		// Load Weave
		g_WeaveLoader.Initialize( );
		g_WeaveLoader.InvokeOEP( );

		util::console::set_prefix( util::console::NONE );
		util::console::print( "finished.\n" );

		hooked_everything = true;
	}
	catch ( const std::runtime_error& error ) {
		MessageBoxA( NULL , error.what( ) , "DEBUG" , MB_OK | MB_ICONERROR );
		FreeLibraryAndExitThread( HMODULE( mod ) , 0 );
		std::abort( );
	}

	return EXIT_SUCCESS;
}

int __stdcall DllMain( HINSTANCE inst , std::uint32_t reason , void* reserved )
{
	if ( reason == DLL_PROCESS_ATTACH ) {
		CreateThread( nullptr , 0 , LPTHREAD_START_ROUTINE( init ) , HMODULE( inst ) , 0 , nullptr );
	}

	return TRUE;
}

