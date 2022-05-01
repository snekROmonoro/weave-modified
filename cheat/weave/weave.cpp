#include "weave.hpp"
#include "../includes.hpp"

void CSettings::Load( )
{
	this->szNewUsername = "we are on cox";
	this->bChangeMenuStyle = true;
	this->bRemoveBlur = true;
	this->bCustomClantag = true;
}

// we could declare this function in utils but yeah
void nop_( PVOID address , int bytes ) {
	constexpr auto NOP = 0x90;

	DWORD d , ds;
	VirtualProtect( address , bytes , PAGE_EXECUTE_READWRITE , &d );
	memset( address , NOP , bytes );
	VirtualProtect( address , bytes , d , &ds );
}

void CLoader::CallbackBeforeOEP( )
{
	/* change username */ {
		// line where used (in initialize thread): weave.dll+DB39D
		// weave.su free string: weave.dll+37DC60

		void* pointer_to_username = ( void* ) ( m_LoaderData.m_base + 0x37DC60 );
		strcpy( ( char* ) pointer_to_username , g_Settings.szNewUsername.c_str( ) );
	}

	/* fix bhop */ {
		// jnz ... -> jmp ...
		// 75 23 -> EB 23
		// address: weave.dll+0x17D727

		std::vector< BYTE > bytes = { 0xEB , 0x23 };
		memcpy( ( void* ) ( m_LoaderData.m_base + 0x17D727 ) , ( void* ) ( bytes.data( ) ) , bytes.size( ) );

		// todo: remove (shouldRecharge) check from bhop
	}

	/* useless tickbase++ in RunCommand, when command shouldn't be run */ {

		/*
			[leito] Allocated virtual memory to 0x48750000
			to nop from 488BB0FC to 488BB12F (included, which is 2 bytes)

			= from weave.dll+0x16B0FC to weave.dll+0x16B12F (included, which is 2 bytes)
		*/

		nop_( ( void* ) ( m_LoaderData.m_base + 0x16B0FC ) , ( 0x16B12F - 0x16B0FC + 2 ) );
	}

	// Change menu style
	if ( g_Settings.bChangeMenuStyle )
	{
		// nop every call to InitStyle
		{
			// fn: InitStyle: @weave.dll+1502B0
			// g_pMenuStyle = @weave.dll+32DBE10

			// Config::ResetToDefault calls to InitStyle
			nop_( ( void* ) ( m_LoaderData.m_base + 0x2BAB9C ) , 5 );
			nop_( ( void* ) ( m_LoaderData.m_base + 0x2BABA1 ) , 5 );

			// Menu::Render calls to InitStyle
			nop_( ( void* ) ( m_LoaderData.m_base + 0x25C5AF ) , 5 );
			nop_( ( void* ) ( m_LoaderData.m_base + 0x25C5B4 ) , 5 );
		}

		// nop stuff that sets colors inside of style
		{
			// Config::Load
			// from weave.dll+2C7438 to weave.dll+2C752C
			nop_( ( void* ) ( m_LoaderData.m_base + 0x2C7438 ) , ( 0x2C752C - 0x2C7438 + 5 ) ); // +5 because we have to nop the last line, which is a jmp

			// we could also nop it from Config::Save but who cares about that, right?
			// let people that don't have our weave version but have a config for it to load them axaxa
		}

		// nop the color picker of accented color
		{
			// from weave.dll+0x270BC0 to weave.dll+0x270C2D we have the color picker
			// and then, after that, until weave.dll+0x270D12 we have the text
			nop_( ( void* ) ( m_LoaderData.m_base + 0x270BC0 ) , ( 0x270D12 - 0x270BC0 + 5 ) ); // +5 because we have to nop the last line, which is a call
		}

		// change blur color
		{
			constexpr auto PUSH_opcode = 0x6A;
			const int new_r = 28;
			const int new_g = 24;
			const int new_b = 28;

			// blue
			void* p = ( void* ) ( m_LoaderData.m_base + 0x15D704 );
			BYTE new_bytes [ 2 ] = { PUSH_opcode , new_b };
			memcpy( p , new_bytes , sizeof( new_bytes ) );

			// green
			p = ( void* ) ( m_LoaderData.m_base + 0x15D706 );
			new_bytes [ 1 ] = new_g;
			memcpy( p , new_bytes , sizeof( new_bytes ) );

			// red
			p = ( void* ) ( m_LoaderData.m_base + 0x15D708 );
			new_bytes [ 1 ] = new_r;
			memcpy( p , new_bytes , sizeof( new_bytes ) );
		}
	}

	// update 26 april 2022
	{

		// address, byte_vector
#define BYTE_PATCH(address, byte_vector) memcpy((void*)(address), (void*)(byte_vector.data()), byte_vector.size());

		/*
			Allocated virtual memory to 0x46F00000

			function where this is: CInput::GetUserCmd
			opcodes: 03 82 F4 00 00 00
			address: 4707D3E8
			offset from allocation address: 0x17D3E8

			function where this is: CInput::GetVerifiedUserCmd
			opcodes: 03 82 F8 00 00 00
			address: 4707D418
			offset from allocation address: 0x17D418

			function where this is: CMisc::CopyCommand
			opcodes: 03 90 F4 00 00 00
			address: 471967F9
			offset from allocation address: 0x2967F9
			stuff to fix: m_pCommands

			function where this is: Hooks::OverrideView
			opcodes: 0F B6 88 AD 00 00 00
			address: 47075626
			offset from allocation address: 0x175626
			stuff to fix: bCameraInThirdPerson

			function where this is: Hooks::OverrideView
			opcodes: F3 0F 10 82 B4 00 00 00
			address: 47075645
			offset from allocation address: 0x175645
			stuff to fix: m_vecCameraOffset.x

			function where this is: Hooks::OverrideView
			opcodes: F3 0F 10 80 B0 00 00 00
			address: 47075658
			offset from allocation address: 0x175658
			stuff to fix: m_vecCameraOffset.y

			function where this is: Hooks::OverrideView
			opcodes: F3 0F 10 82 B8 00 00 00
			address: 47075698
			offset from allocation address: 0x175698
			stuff to fix: m_vecCameraOffset.z

			function where this is: Thirdperson
			opcodes: 0F B6 91 AD 00 00 00
			address: 47074EA0
			offset from allocation address: 0x174EA0
			stuff to fix: bCameraInThirdPerson

			function where this is: Thirdperson
			opcodes: C6 80 AD 00 00 00 01
			address: 47074EB0
			offset from allocation address: 0x174EB0
			stuff to fix: bCameraInThirdPerson

			function where this is: Thirdperson
			opcodes: 0F B6 91 AD 00 00 00
			address: 47074EBD
			offset from allocation address: 0x174EBD
			stuff to fix: bCameraInThirdPerson

			function where this is: Thirdperson
			opcodes: C6 80 AD 00 00 00 00
			address: 47075234
			offset from allocation address: 0x175234
			stuff to fix: bCameraInThirdPerson

			function where this is: Thirdperson
			opcodes: 81 C1 B0 00 00 00
			address: 47075222
			offset from allocation address: 0x175222
			stuff to fix: m_vecCameraOffset

			function where this is: Thirdperson
			opcodes: F3 0F 11 81 B8 00 00 00
			address: 47075244
			offset from allocation address: 0x175244
			stuff to fix: m_vecCameraOffset.z

			function where this is: Hooks::FrameStageNotify
			opcodes: C6 82 AD 00 00 00 00
			address: 47070620
			offset from allocation address: 0x170620
			stuff to fix: bCameraInThirdPerson

			function where this is: Hooks::CreateMove
			opcodes: 8B 88 F4 00 00 00
			address: 4706C28B
			offset from allocation address:
			stuff to fix: m_pCommands

			function where this is: Hooks::CreateMove
			opcodes: 8B 88 F4 00 00 00
			address: 4706C2C4
			offset from allocation address: 0x16C28B
			stuff to fix: m_pCommands

			function where this is: Hooks::CreateMove
			opcodes: 8B 88 F4 00 00 00
			address: 4706C2FB
			offset from allocation address: 0x16C2FB
			stuff to fix: m_pCommands

			function where this is: Hooks::PacketEnd
			opcodes: 03 90 F4 00 00 00
			address: 4706A8B6
			offset from allocation address: 0x16A8B6
			stuff to fix: m_pCommands

			function where this is: Hooks::PacketEnd
			opcodes: 03 90 F8 00 00 00
			address: 4706A8D4
			offset from allocation address: 0x16A8D4
			stuff to fix: m_pVerifiedCommands

			function where this is: Glow::Draw
			opcodes: 0F B6 91 AD 00 00 00
			address: 4703B018
			offset from allocation address: 0x13B018
			stuff to fix: bCameraInThirdPerson

			function where this is: sub_100C9080
			opcodes: 0F B6 91 AD 00 00 00
			address: 46FC94BF
			offset from allocation address: 0xC94BF
			stuff to fix: bCameraInThirdPerson
		*/

		std::vector< BYTE > bytes;

		// CInput::GetUserCmd
		bytes = { 0x03 , 0x82 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x17D3E8 , bytes );

		// CInput::GetVerifiedUserCmd
		bytes = { 0x03 , 0x82 , 0xF4 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x17D418 , bytes );

		// CMisc::CopyCommand
		bytes = { 0x03 , 0x90 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x2967F9 , bytes );

		// Hooks::OverrideView
		bytes = { 0x0F , 0xB6 , 0x88 , 0xA9 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175626 , bytes );

		// Hooks::OverrideView
		bytes = { 0xF3 , 0x0F , 0x10 , 0x82 , 0xB0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175645 , bytes );

		// Hooks::OverrideView
		bytes = { 0xF3 , 0x0F , 0x10 , 0x80 , 0xAC , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175658 , bytes );

		// Hooks::OverrideView
		bytes = { 0xF3 , 0x0F , 0x10 , 0x82 , 0xB4 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175698 , bytes );

		// Thirdperson
		bytes = { 0x0F , 0xB6 , 0x91 , 0xA9 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x174EA0 , bytes );

		// Thirdperson
		bytes = { 0xC6 , 0x80 , 0xA9 , 0x00 , 0x00 , 0x00 , 0x01 };
		BYTE_PATCH( m_LoaderData.m_base + 0x174EB0 , bytes );

		// Thirdperson
		bytes = { 0x0F , 0xB6 , 0x91 , 0xA9 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x174EBD , bytes );

		// Thirdperson
		bytes = { 0xC6 , 0x80 , 0xA9 , 0x00 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175234 , bytes );

		// Thirdperson
		bytes = { 0x81 , 0xC1 , 0xAC , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175222 , bytes );

		// Thirdperson
		bytes = { 0xF3 , 0x0F , 0x11 , 0x81 , 0xB4 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x175244 , bytes );

		// Hooks::FrameStageNotify
		bytes = { 0xC6 , 0x82 , 0xA9 , 0x00 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x170620 , bytes );

		// Hooks::CreateMove
		bytes = { 0x8B , 0x88 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x16C28B , bytes );

		// Hooks::CreateMove
		bytes = { 0x8B , 0x88 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x16C28B , bytes );

		// Hooks::CreateMove
		bytes = { 0x8B , 0x88 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x16C2FB , bytes );

		// Hooks::PacketEnd
		bytes = { 0x03 , 0x90 , 0xF0 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x16A8B6 , bytes );

		// Hooks::PacketEnd
		bytes = { 0x03 , 0x90 , 0xF4 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x16A8D4 , bytes );

		// Glow::Draw
		bytes = { 0x0F , 0xB6 , 0x91 , 0xA9 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0x13B018 , bytes );

		// sub_100C9080
		bytes = { 0x0F , 0xB6 , 0x91 , 0xA9 , 0x00 , 0x00 , 0x00 };
		BYTE_PATCH( m_LoaderData.m_base + 0xC94BF , bytes );

#undef BYTE_PATCH
	}
}

void CLoader::CallbackAfterOEP( )
{
	// Change menu style
	if ( g_Settings.bChangeMenuStyle )
	{
		// fn: InitStyle: @weave.dll+1502B0
		// g_pMenuStyle = @weave.dll+32DBE10

		void* pInitStyleFn = ( void* ) ( m_LoaderData.m_base + 0x1502B0 );
		void* pMenuStyle = ( void* ) ( m_LoaderData.m_base + 0x32DBE10 );
		// pMenuStyle[0] = g_pCfg::DebugMode

		// call InitStyle
		/*__asm {
			mov ecx, pMenuStyle
			call pInitStyleFn
		}*/
		( ( void( __thiscall* )( void* ) )pInitStyleFn )( pMenuStyle );

		auto set_new_color = [ ] ( void* address , color_t new_col ) {
			DWORD oldprotect;
			VirtualProtect( address , sizeof( color_t ) , PAGE_EXECUTE_READWRITE , &oldprotect );

			int r , g , b , a;
			new_col.get( r , g , b , a );

			color_t& col = *( color_t* ) address;
			col.set( r , g , b , a );

			VirtualProtect( address , sizeof( color_t ) , oldprotect , &oldprotect );
		};

		auto get_color_address_from_style = [ & ] ( int a1 ) {
			// ida, but this would be pMenuStyle[a1]
			// and also +1 because first variable is DebugMode
			return ( void* ) ( ( int ) pMenuStyle + 4 * a1 + 1 );
		};

		// set colors so we are funny

		// accented color
		set_new_color( get_color_address_from_style( 0 ) , color_t( 156 , 25 , 168 ) );

		// menu background
		// color_t( 59 , 37 , 61 )
		set_new_color( get_color_address_from_style( 1 ) , color_t( 28 , 24 , 28 ) );
		set_new_color( get_color_address_from_style( 2 ) , color_t( 28 , 24 , 28 ) );

		// child background
		set_new_color( get_color_address_from_style( 3 ) , color_t( 43 , 37 , 43 ) );
		set_new_color( get_color_address_from_style( 4 ) , color_t( 43 , 37 , 43 ) );
	}

	// Hook stuff
	if ( !util::hook::hook_address( ( void* ) ( m_LoaderData.m_base + 0x20FCD0 ) , WeaveHooks::hkWeaveDrawBlur , &WeaveHooks::ohkWeaveDrawBlur ) )
		throw std::runtime_error( "failed to hook hkWeaveDrawBlur" );

	if ( !util::hook::hook_address( ( void* ) ( m_LoaderData.m_base + 0x293DC0 ) , WeaveHooks::hkWeaveSetClanTag , &WeaveHooks::ohkWeaveSetClanTag ) )
		throw std::runtime_error( "failed to hook hkWeaveSetClanTag" );

	// Log that it loaded
	// void __cdecl AddEventLog(int str, int a2, int a3, int a4, int a5, int a6, char bShouldNotOutputConsole)
	( ( void( __cdecl* )( std::string str , int a2 , int a3 , int a4 , int a5 , int a6 , bool bShouldNotOutputConsole ) )( m_LoaderData.m_base + 0x169B60 ) )( "weave.modified loaded successfully" , 0 , 0 , 0 , 0 , 0 , false );
}

int __cdecl WeaveHooks::hkWeaveDrawBlur( int a1 , int a2 , int a3 , int a4 , int a5 , int a6 , int a7 , int a8 , int a9 , int a10 , int a11 )
{
	/*
		arguments:
		a1 = pImGuiRendering
		a2 = first position X
		a3 = first position Y
		a4 = second position X
		a5 = second position Y
		a6 = float[0-1] Color Red
		a7 = float[0-1] Color Green
		a8 = float[0-1] Color Blue
		a9 = @not used@
		a10 = a11 = rounding
	*/

	if ( g_Settings.bRemoveBlur )
		return 0;

	return ohkWeaveDrawBlur(
		a1 ,
		a2 ,
		a3 ,
		a4 ,
		a5 ,
		a6 ,
		a7 ,
		a8 ,
		a9 ,
		a10 ,
		a11 );
}

void __fastcall WeaveHooks::hkWeaveSetClanTag( REG , const char* tag , const char* name )
{
	if ( g_Settings.bCustomClantag )
	{
		/*
			[warn] WeaveSetClanTag: tag[w    ], name[weave.su]
			[warn] WeaveSetClanTag: tag[we   ], name[weave.su]
			[warn] WeaveSetClanTag: tag[we-  ], name[weave.su]
			[warn] WeaveSetClanTag: tag[wea- ], name[weave.su]
			[warn] WeaveSetClanTag: tag[weav ], name[weave.su]
			[warn] WeaveSetClanTag: tag[weav-], name[weave.su]
			[warn] WeaveSetClanTag: tag[weav3], name[weave.su]
			[warn] WeaveSetClanTag: tag[w3ave], name[weave.su]
			[warn] WeaveSetClanTag: tag[weav-], name[weave.su]
			[warn] WeaveSetClanTag: tag[wea  ], name[weave.su]
			[warn] WeaveSetClanTag: tag[we   ], name[weave.su]
			[warn] WeaveSetClanTag: tag[we-  ], name[weave.su]
			[warn] WeaveSetClanTag: tag[w-   ], name[weave.su]
		*/

		if ( std::string( name ) == "weave.su" ) {
			std::string tag_str = std::string( tag );

			int i = -1;
			if ( tag_str == "w    " ) {
				i = 0;
			}
			else if ( tag_str == "we   " ) {
				i = 1;
			}
			else if ( tag_str == "we-  " ) {
				i = 2;
			}
			else if ( tag_str == "wea- " ) {
				i = 3;
			}
			else if ( tag_str == "weav " ) {
				i = 4;
			}
			else if ( tag_str == "weav-" ) {
				i = 5;
			}
			else if ( tag_str == "weav3" ) {
				i = 6;
			}
			else if ( tag_str == "w3ave" ) {
				i = 7;
			}

			/* idea:
				static int i = 0;
				i++;
				if ( tag_str == "w    " ) { i = 0; }
			*/

			std::string new_name = "weave.who";

			switch ( i )
			{
			case 0: {
				ohkWeaveSetClanTag( REG_OUT , "weave.who" , new_name.c_str( ) );
			} break;
			case 1: {
				ohkWeaveSetClanTag( REG_OUT , "weave.wh?" , new_name.c_str( ) );
			} break;
			case 2: {
				ohkWeaveSetClanTag( REG_OUT , "weave.w? " , new_name.c_str( ) );
			} break;
			case 3: {
				ohkWeaveSetClanTag( REG_OUT , "weave.?  " , new_name.c_str( ) );
			} break;
			case 4: {
				ohkWeaveSetClanTag( REG_OUT , "weave?   " , new_name.c_str( ) );
			} break;
			case 5: {
				ohkWeaveSetClanTag( REG_OUT , "??????   " , new_name.c_str( ) );
			} break;
			case 6: {
				ohkWeaveSetClanTag( REG_OUT , "weave.   " , new_name.c_str( ) );
			} break;
			case 7: {
				ohkWeaveSetClanTag( REG_OUT , "weave.who" , new_name.c_str( ) );
			} break;

			default: {
				ohkWeaveSetClanTag( REG_OUT , "weave.who" , new_name.c_str( ) );
			}
			}

			return;
		}
	}

	return ohkWeaveSetClanTag( REG_OUT , tag , name );
}
