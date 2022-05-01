#pragma once
#include <windows.h>
#include <algorithm>
#include <string>
#include "../Loader/loader.hpp"

// colors are uint8_t[4] in weave, don't ask
class color_t {
public:
	color_t( )
	{
		*( uint32_t* ) _color = 0;
	}

	color_t( int color32 )
	{
		*( uint32_t* ) _color = color32;
	}

	color_t( int _r , int _g , int _b )
	{
		set( _r , _g , _b , 255 );
	}

	color_t( int _r , int _g , int _b , int _a )
	{
		set( _r , _g , _b , _a );
	}

	void set( int _r , int _g , int _b , int _a = 255 )
	{
		_color [ 0 ] = std::clamp( _r , 0 , 255 );
		_color [ 1 ] = std::clamp( _g , 0 , 255 );
		_color [ 2 ] = std::clamp( _b , 0 , 255 );
		_color [ 3 ] = std::clamp( _a , 0 , 255 );
	}

	void get( int& _r , int& _g , int& _b , int& _a ) const
	{
		_r = _color [ 0 ];
		_g = _color [ 1 ];
		_b = _color [ 2 ];
		_a = _color [ 3 ];
	}
private:
	uint8_t _color [ 4 ];
};

class CSettings
{
public:
	void Load( );
	std::string szNewUsername;
	bool bChangeMenuStyle;
	bool bRemoveBlur;
	bool bCustomClantag;
};

inline CSettings g_Settings;

class CLoader : public CBaseLoader
{
public:
	void CallbackBeforeOEP( ) override;
	void CallbackAfterOEP( ) override;
};

inline CLoader g_WeaveLoader;

// todo: move these two somewhere else
#define REG void* ecx, void* edx
#define REG_OUT ecx, edx

namespace WeaveHooks
{
	int __cdecl hkWeaveDrawBlur( int a1 , int a2 , int a3 , int a4 , int a5 , int a6 , int a7 , int a8 , int a9 , int a10 , int a11 );
	inline decltype( &hkWeaveDrawBlur ) ohkWeaveDrawBlur = nullptr;

	void __fastcall hkWeaveSetClanTag( REG , const char* tag , const char* name );
	inline decltype( &hkWeaveSetClanTag ) ohkWeaveSetClanTag = nullptr;
}