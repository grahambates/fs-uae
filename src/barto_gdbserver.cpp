#include "sysconfig.h"
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#endif

#include "sysdeps.h"

#include <thread>
#include <vector>
#include <array>

#include "options.h"
#include "memory.h"
#include "newcpu.h"
#include "debug.h"
#include "inputdevice.h"
#include "uae.h"
#include "debugmem.h"
#include "custom.h"
#include "xwin.h" // xcolnr
#include "drawing.h" // color_entry
#include "savestate.h"
#include "fsemu-log.h"
#include "fsemu-action.h"
#include "fsemu-video.h"
#include "fs/conf.h"

#define OPTION_REMOTE_DEBUGGER_START_TIMER "remote_debugger"
#define OPTION_REMOTE_DEBUGGER_TRIGGER "remote_debugger_trigger"
#define OPTION_REMOTE_DEBUGGER_PORT "remote_debugger_port"
#define DEFAULT_PORT 2345

#define GDB_ACK                                  "+"
#define GDB_OK                                   "OK"

#define GDBERROR_PACKET_NOT_SUPPORTED            ""    // Packet not supported
#define GDBERROR_PROCESSING                      "E01" // General error during processing
#define GDBERROR_PARSE                           "E02" // Error during the packet parse
#define GDBERROR_UNSUPPORTED_COMMAND             "E03" // Unsupported / unknown command
#define GDBERROR_UNKOWN_REGISTER                 "E04" // Unknown register
#define GDBERROR_INVALID_FRAME_ID                "E05" // Invalid Frame Id
#define GDBERROR_INVALID_MEMORY_LOCATION         "E06" // Invalid memory location
#define GDBERROR_INVALID_ADDRESS                 "E07" // Address not safe for a set memory command
#define GDBERROR_INVALID_BREAKPOINT              "E08" // Unknown breakpoint
#define GDBERROR_MAX_BREAKPOINTS_REACHED         "E09" // The maximum of breakpoints have been reached

// Size of the communication buffer
#define BUFFER_SIZE 512

#ifdef _WIN32
	#define sock_err WSAGetLastError()
#else
	#define sock_err errno
	#define closesocket ::close
#endif

#ifndef _countof
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#ifndef SOCKADDR_INET
#define SOCKADDR_INET -1
#endif

#define STRINGIZE_(x) #x
#define STRINGIZE(x) STRINGIZE_(x)

#define barto_log(format, ...) fsemu_log_info(format, ##__VA_ARGS__)

// from newcpu.cpp
/*static*/ extern int baseclock;

// from custom.cpp
/*static*/ extern struct color_entry current_colors;
extern uae_u8 *save_custom(size_t *len, uae_u8 *dstptr, int full);
extern int debug_safe_addr(uaecptr addr, int size);

// from debug.cpp
extern uae_u8 *get_real_address_debug(uaecptr addr);
extern void initialize_memwatch(int mode);
extern void memwatch_setup();
/*static*/ extern int trace_mode;
/*static*/ extern uae_u32 trace_param[2];
/*static*/ extern uaecptr processptr;
/*static*/ extern uae_char *processname;
/*static*/ extern int memwatch_triggered;
/*static*/ extern struct memwatch_node mwhit;
extern int debug_illegal;
extern uae_u64 debug_illegal_mask;
/*static*/ extern bool debug_line(TCHAR *input);

#define NR_DMA_REC_HPOS 256
#define NR_DMA_REC_VPOS 1000

// from writelog_fs.cpp
extern void capture_start();
extern TCHAR *capture_end();

// from fsvideo.cpp
extern fsemu_video_frame_t *uae_fsvideo_getframe();

#include "barto_gdbserver.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

// VS2022: Test or Release/FullRelease config 
// -s input.config=1 -s input.1.keyboard.0.button.41.GRAVE=SPC_SINGLESTEP.0    -s use_gui=no -s quickstart=a500,1 -s debugging_features=gdbserver -s filesystem=rw,dh0:c:\Users\Chuck\Documents\Visual_Studio_Code\amiga-debug\bin\dh0
// c:\Users\Chuck\Documents\Visual_Studio_Code\amiga-debug\bin\opt\bin> m68k-amiga-elf-gdb.exe -ex "set debug remote 1" -ex "target remote :2345" -ex "monitor profile xxx" ..\..\..\template\a.mingw.elf

namespace barto_gdbserver {
	bool is_connected();
	bool data_available();
	void disconnect();
	void set_exception(int n);

	// Options:
	bool enabled = false;
	int port = DEFAULT_PORT;
	int time_out;
	char *debugging_trigger;

	static bool in_handle_packet = false;
	struct tracker {
		tracker() { backup = in_handle_packet; in_handle_packet = true; }
		~tracker() { in_handle_packet = backup; }
	private: 
		bool backup;
	};

	static std::string string_replace_all(const std::string& str, const std::string& search, const std::string& replace) {
		std::string copy(str);
		size_t start = 0;
		for(;;) {
			auto p = copy.find(search, start);
			if(p == std::string::npos)
				break;

			copy.replace(p, search.size(), replace);
			start = p + replace.size();
		}
		return copy;
	}

	/*
	static std::string string_to_utf8(LPCWSTR string) {
		int len = WideCharToMultiByte(CP_UTF8, 0, string, -1, nullptr, 0, nullptr, nullptr);
		std::unique_ptr<char[]> buffer(new char[len]);
		WideCharToMultiByte(CP_UTF8, 0, string, -1, buffer.get(), len, nullptr, nullptr);
		wcstombs(buffer.get(), string, len);
		return std::string(buffer.get());
	}
	*/

	static constexpr char hex[]{ "0123456789abcdef" };
	static std::string hex8(uint8_t v) {
		std::string ret;
		ret += hex[v >> 4];
		ret += hex[v & 0xf];
		return ret;
	}
	static std::string hex32(uint32_t v) {
		std::string ret;
		for(int i = 28; i >= 0; i -= 4)
			ret += hex[(v >> i) & 0xf];
		return ret;
	}

	static std::string from_hex(const std::string& s) {
		std::string ret;
		for(size_t i = 0, len = s.length() & ~1; i < len; i += 2) {
			uint8_t v{};
			if(s[i] >= '0' && s[i] <= '9')
				v |= (s[i] - '0') << 4;
			else if(s[i] >= 'a' && s[i] <= 'f')
				v |= (s[i] - 'a' + 10) << 4;
			else if(s[i] >= 'A' && s[i] <= 'F')
				v |= (s[i] - 'A' + 10) << 4;
			if(s[i + 1] >= '0' && s[i + 1] <= '9')
				v |= (s[i + 1] - '0');
			else if(s[i + 1] >= 'a' && s[i + 1] <= 'f')
				v |= (s[i + 1] - 'a' + 10);
			else if(s[i + 1] >= 'A' && s[i + 1] <= 'F')
				v |= (s[i + 1] - 'A' + 10);
			ret += (char)v;
		}
		return ret;
	}

	static std::string to_hex(const std::string& s) {
		std::string ret;
		for(size_t i = 0, len = s.length(); i < len; i++) {
			uint8_t v = s[i];
			ret += hex[v >> 4];
			ret += hex[v & 0xf];
		}
		return ret;
	}

/*	#pragma comment(lib, "Bcrypt.lib")
	#ifndef NT_SUCCESS
		#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
	#endif
	std::array<uint8_t, 32> sha256(const void* addr, size_t size) {
		std::array<uint8_t, 32> hash{};

		BCRYPT_ALG_HANDLE AlgHandle = nullptr;
		BCRYPT_HASH_HANDLE HashHandle = nullptr;
		if(NT_SUCCESS(BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG))) {
			DWORD HashLength = 0;
			DWORD ResultLength = 0;
			if(NT_SUCCESS(BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&HashLength, sizeof(HashLength), &ResultLength, 0)) && HashLength == hash.size()) {
				if(NT_SUCCESS(BCryptCreateHash(AlgHandle, &HashHandle, nullptr, 0, nullptr, 0, 0))) {
					(void)BCryptHashData(HashHandle, kickmem_bank.baseaddr, kickmem_bank.allocated_size, 0);
					(void)BCryptFinishHash(HashHandle, hash.data(), (ULONG)hash.size(), 0);
					BCryptDestroyHash(HashHandle);
				}
			}
			BCryptCloseAlgorithmProvider(AlgHandle, 0);
		}

		return hash;
	}

	std::array<uint8_t, 16> sha1(const void* addr, size_t size) {
		std::array<uint8_t, 16> hash{};

		BCRYPT_ALG_HANDLE AlgHandle = nullptr;
		BCRYPT_HASH_HANDLE HashHandle = nullptr;
		if(NT_SUCCESS(BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG))) {
			DWORD HashLength = 0;
			DWORD ResultLength = 0;
			if(NT_SUCCESS(BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&HashLength, sizeof(HashLength), &ResultLength, 0)) && HashLength == hash.size()) {
				if(NT_SUCCESS(BCryptCreateHash(AlgHandle, &HashHandle, nullptr, 0, nullptr, 0, 0))) {
					(void)BCryptHashData(HashHandle, kickmem_bank.baseaddr, kickmem_bank.allocated_size, 0);
					(void)BCryptFinishHash(HashHandle, hash.data(), (ULONG)hash.size(), 0);
					BCryptDestroyHash(HashHandle);
				}
			}
			BCryptCloseAlgorithmProvider(AlgHandle, 0);
		}

		return hash;
	}
*/

/*	#pragma comment(lib, "Bcrypt.lib")
	#ifndef NT_SUCCESS
		#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
	#endif
	std::array<uint8_t, 32> sha256(const void* addr, size_t size) {
		std::array<uint8_t, 32> hash{};

		BCRYPT_ALG_HANDLE AlgHandle = nullptr;
		BCRYPT_HASH_HANDLE HashHandle = nullptr;
		if(NT_SUCCESS(BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG))) {
			DWORD HashLength = 0;
			DWORD ResultLength = 0;
			if(NT_SUCCESS(BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&HashLength, sizeof(HashLength), &ResultLength, 0)) && HashLength == hash.size()) {
				if(NT_SUCCESS(BCryptCreateHash(AlgHandle, &HashHandle, nullptr, 0, nullptr, 0, 0))) {
					(void)BCryptHashData(HashHandle, kickmem_bank.baseaddr, kickmem_bank.allocated_size, 0);
					(void)BCryptFinishHash(HashHandle, hash.data(), (ULONG)hash.size(), 0);
					BCryptDestroyHash(HashHandle);
				}
			}
			BCryptCloseAlgorithmProvider(AlgHandle, 0);
		}

		return hash;
	}

	std::array<uint8_t, 16> sha1(const void* addr, size_t size) {
		std::array<uint8_t, 16> hash{};

		BCRYPT_ALG_HANDLE AlgHandle = nullptr;
		BCRYPT_HASH_HANDLE HashHandle = nullptr;
		if(NT_SUCCESS(BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG))) {
			DWORD HashLength = 0;
			DWORD ResultLength = 0;
			if(NT_SUCCESS(BCryptGetProperty(AlgHandle, BCRYPT_HASH_LENGTH, (PBYTE)&HashLength, sizeof(HashLength), &ResultLength, 0)) && HashLength == hash.size()) {
				if(NT_SUCCESS(BCryptCreateHash(AlgHandle, &HashHandle, nullptr, 0, nullptr, 0, 0))) {
					(void)BCryptHashData(HashHandle, kickmem_bank.baseaddr, kickmem_bank.allocated_size, 0);
					(void)BCryptFinishHash(HashHandle, hash.data(), (ULONG)hash.size(), 0);
					BCryptDestroyHash(HashHandle);
				}
			}
			BCryptCloseAlgorithmProvider(AlgHandle, 0);
		}

		return hash;
	}
*/

	std::thread connect_thread;
	SOCKET gdbsocket{ INVALID_SOCKET };
	SOCKET gdbconn{ INVALID_SOCKET };
	char socketaddr[sizeof SOCKADDR_INET];
	bool useAck{ true };
	uint32_t baseText{};
	uint32_t sizeText{};
	uint32_t systemStackLower{}, systemStackUpper{};
	uint32_t stackLower{}, stackUpper{};
	std::vector<uint32_t> sections; // base for every section
	std::string profile_outname;
	int profile_num_frames{};
	int profile_frame_count{};
	std::unique_ptr<cpu_profiler_unwind[]> profile_unwind{};
	#define DEFAULT_TRACEFRAME -1		// Traceframe default index
	int current_traceframe = DEFAULT_TRACEFRAME;
	#define THREAD_ID_CPU    1		// Id for the cpu thread
	#define THREAD_ID_COPPER 2		// Id for the copper thread
	std::string stop_signal = "S05";
	int exception_no{};

	enum class state {
		inited,
		connected,
		debugging,
		profile,
		profiling,
	};

	state debugger_state{ state::inited };

	bool is_enabled() {
		return enabled;
	}

	bool is_connected() {
		if(gdbsocket == INVALID_SOCKET)
			return false;
		if(gdbconn == INVALID_SOCKET) {
			struct timeval tv;
			fd_set fd;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			FD_ZERO(&fd);
			FD_SET(gdbsocket, &fd);
			if(select(gdbsocket + 1, &fd, NULL, NULL, &tv)) {
				unsigned int hostSize = sizeof(struct sockaddr_in);
				gdbconn = accept(gdbsocket, (struct sockaddr*)socketaddr, (socklen_t*)&hostSize);
				if(gdbconn != INVALID_SOCKET)
					barto_log("connection accepted\n");
			}
		}
		return gdbconn != INVALID_SOCKET;
	}

	bool data_available() {
		if(is_connected()) {
			struct timeval tv;
			fd_set fd;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			FD_ZERO(&fd);
			FD_SET(gdbconn, &fd);
			int err = select(gdbconn + 1, &fd, nullptr, nullptr, &tv);
			if(err == SOCKET_ERROR) {
				disconnect();
				return false;
			}
			if(err > 0)
				return true;
		}
		return false;
	}

	bool listen() {
		barto_log("GDBSERVER: listen()\n");

		assert(debugger_state == state::inited);

		#ifdef _WIN32
		WSADATA wsaData = { 0 };
		if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			barto_log(_T("GDBSERVER: can't open winsock, error %d\n"), sock_err);
			return false;
		}
		#endif

		int err;
		const int one = 1;
		const struct linger linger_1s = { 1, 1 };
		constexpr auto name = _T("127.0.0.1");

		sockaddr_in serv_addr;
		serv_addr.sin_family=AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr(name);
		serv_addr.sin_port = htons(port);

		gdbsocket = socket(AF_INET, SOCK_STREAM, 0);
		if(gdbsocket == INVALID_SOCKET) {
			barto_log(_T("GDBSERVER: socket() failed, %d\n"), sock_err);
			return false;
		}
		if(setsockopt(gdbsocket, SOL_SOCKET, SO_LINGER, (char*)&linger_1s, sizeof linger_1s) < 0) {
			barto_log(_T("GDBSERVER: setsockopt(SO_LINGER) failed, %d\n"), sock_err);
			return false;
		}
		if(setsockopt(gdbsocket, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof one) < 0) {
			barto_log(_T("GDBSERVER: setsockopt(SO_REUSEADDR) failed, %d\n"), sock_err);
			return false;
		}
		if(::bind(gdbsocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
			barto_log(_T("GDBSERVER: bind() failed, %s:%d: %d\n"), name, port, sock_err);
			return false;
		}
		if(::listen(gdbsocket, 1) < 0) {
			barto_log(_T("GDBSERVER: listen() failed, %s:%d: %d\n"), name, port, sock_err);
			return false;
		}

		barto_log("GDBSERVER: listen() succeeded on %s:%d\n", name, port);
		return true;
	}

	bool init() {
		// Read options:
		if(fs_config_exists(OPTION_REMOTE_DEBUGGER_START_TIMER)) {
			enabled = true;
			time_out = fs_config_get_int(OPTION_REMOTE_DEBUGGER_START_TIMER);
		}
		if(fs_config_exists(OPTION_REMOTE_DEBUGGER_TRIGGER)) {
			debugging_trigger = fs_config_get_string(OPTION_REMOTE_DEBUGGER_TRIGGER);
		}
		if(fs_config_exists(OPTION_REMOTE_DEBUGGER_PORT)) {
			port = fs_config_get_int(OPTION_REMOTE_DEBUGGER_PORT);
		}

		if(enabled) {
			barto_log(_T("GDBSERVER: enabled (start_timer: %d trigger: %s port: %d)\n"), time_out, debugging_trigger, port);
			close();

			fsemu_action_process_command_in_main(FSEMU_ACTION_WARP, 1);

			// disable console
			static TCHAR empty[2] = { 0 };
			setconsolemode(empty, 1);

			activate_debugger();
			initialize_memwatch(0);

			if(debugging_trigger) {
				// from debug.cpp@process_breakpoint()
				processptr = 0;
				xfree(processname);
				processname = nullptr;
				processname = debugging_trigger;
				trace_mode = TRACE_CHECKONLY;
			} else {
				// savestate debugging
				baseText = 0;
				sizeText = 0x7fff'ffff;
			}

			// call as early as possible to avoid delays with GDB having to retry to connect...
			listen();
		}

		return true;
	}

	void close() {
		barto_log(_T("GDBSERVER: close()\n"));
		if(gdbconn != INVALID_SOCKET)
			closesocket(gdbconn);
		gdbconn = INVALID_SOCKET;
		if(gdbsocket != INVALID_SOCKET)
			closesocket(gdbsocket);
		gdbsocket = INVALID_SOCKET;
		#ifdef _WIN32
		WSACleanup();
		#endif
	}

	void disconnect() {
		if(gdbconn == INVALID_SOCKET)
			return;
		closesocket(gdbconn);
		gdbconn = INVALID_SOCKET;
		barto_log(_T("GDBSERVER: disconnect\n"));
	}

	void set_exception(int n) {
		exception_no = n;
	}

	// from binutils-gdb/gdb/m68k-tdep.c
/*	static const char* m68k_register_names[] = {
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
		"a0", "a1", "a2", "a3", "a4", "a5", "a6", "sp", //BARTO
		"sr", "pc", //BARTO
		"fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7",
		"fpcontrol", "fpstatus", "fpiaddr"
	}*/
	enum regnames {
		D0, D1, D2, D3, D4, D5, D6, D7,
		A0, A1, A2, A3, A4, A5, A6, A7,
		SR, PC
	};

	static std::string get_register(int reg) {
		uint32_t regvalue{};
		if (current_traceframe < 0) {
			// need to byteswap because GDB expects 68k big-endian
			switch (reg) {
			case SR:
				MakeSR();
				regvalue = regs.sr;
				break;
			case PC:
				regvalue = M68K_GETPC;
				break;
			case D0: case D1: case D2: case D3: case D4: case D5: case D6: case D7:
				regvalue = m68k_dreg(regs, reg - D0);
				break;
			case A0: case A1: case A2: case A3: case A4: case A5: case A6: case A7:
				regvalue = m68k_areg(regs, reg - A0);
				break;
			default:
				return "xxxxxxxx";
			}
		}
		else {
			// Retrive the curren frame
			int tfnum;
			debugstackframe* tframe = debugmem_find_traceframe(false, current_traceframe, &tfnum);
			if (tframe)
			{
				switch (reg) {
				case SR:
					regvalue = tframe->sr;
					break;
				case PC:
					regvalue = tframe->current_pc;
					break;
				case D0: case D1: case D2: case D3: case D4: case D5: case D6: case D7:
					regvalue = tframe->regs[reg - D0];
					break;
				case A0: case A1: case A2: case A3: case A4: case A5: case A6: case A7:
					regvalue = tframe->regs[reg - A0];
					break;
				default:
					return "xxxxxxxx";
				}
			}
			else {
				return GDBERROR_INVALID_FRAME_ID;
			}
		}
		return hex32(regvalue);
	}

	/**
	 * Handles a set register request
	 *`P n`=r`
	 *   Write register n` with value r`. The register number n is in hexadecimal, and r` contains two hex digits for each byte in the register (target byte order).
	 *   Reply:
	 *   `OK`
	 *       for success
	 *   `E NN`
	 *       for an error
	 */
	static std::string set_register(const std::string& request) {
		std::string response = GDB_OK;
		int reg = strtoul(request.data() + 1, nullptr, 16);
		uaecptr value = 0;
		auto eq_pos = request.find('=', 1);
		if (eq_pos != std::string::npos) {
			value = strtoul(request.data() + eq_pos + 1, nullptr, 16);
			switch (reg) {
			case D0: case D1: case D2: case D3: case D4: case D5: case D6: case D7:
				m68k_dreg(regs, reg) = value;
				break;
			case A0: case A1: case A2: case A3: case A4: case A5: case A6: case A7:
				m68k_areg(regs, reg) = value;
				break;
			default:
				response = GDBERROR_UNKOWN_REGISTER;
			}
		}
		else {
			response = GDBERROR_PARSE;
		}
		return response;
	}

	static std::string get_registers(int thread_id) {
		barto_log("GDBSERVER: PC=%x\n", M68K_GETPC);
		std::string ret;
		if ((current_traceframe < 0) || (thread_id == THREAD_ID_COPPER)){
			for (int reg = 0; reg < 18; reg++) {
				if (thread_id == THREAD_ID_COPPER && reg == PC) {
					// Copper PC
					ret += hex32(get_copper_address(-1));
				}
				else {
					ret += get_register(reg);
				}
			}
		}
		else {
			// Retrive the curren frame
			int tfnum;
			debugstackframe* tframe = debugmem_find_traceframe(false, current_traceframe, &tfnum);
			if (tframe)
			{
				for (int reg = 0; reg < 16; reg++)
					ret += hex32(tframe->regs[reg]);
				ret += hex32(tframe->sr);
				ret += hex32(tframe->current_pc);
			}
			else {
				ret = GDBERROR_INVALID_FRAME_ID;
			}
		}
		return ret;
	}

	void print_breakpoints() {
		barto_log("GDBSERVER: Breakpoints:\n");
		for(auto& bpn : bpnodes) {
			if(bpn.enabled) {
				barto_log("GDBSERVER: - %d, 0x%x, 0x%x\n", bpn.type, bpn.value1, bpn.value2);
			}
		}
	}

	void print_watchpoints() {
		barto_log("GDBSERVER: Watchpoints:\n");
		for(auto& mwn : mwnodes) {
			if(mwn.size) {
				barto_log("GDBSERVER: - 0x%x, 0x%x\n", mwn.addr, mwn.size);
			}
		}
	}

	void send_ack(const std::string& ack) {
		if(useAck && !ack.empty()) {
			barto_log("GDBSERVER: <- %s\n", ack.c_str());
			int result = send(gdbconn, ack.data(), (int)ack.length(), 0);
			if(result == SOCKET_ERROR)
				barto_log(_T("GDBSERVER: error sending ack: %d\n"), sock_err);
		}
	}

	void send_response(std::string response) {
		tracker _;
		if(!response.empty()) {
			barto_log("GDBSERVER: <- %s\n", response.substr(1).c_str());
			uint8_t cksum{};
			for(size_t i = 1; i < response.length(); i++)
				cksum += response[i];
			response += '#';
			response += hex[cksum >> 4];
			response += hex[cksum & 0xf];
			int result = send(gdbconn, response.data(), (int)response.length(), 0);
			if(result == SOCKET_ERROR)
				barto_log(_T("GDBSERVER: error sending data: %d\n"), sock_err);
		}
	}
	std::string handle_qoffsets() {
		std::string response = GDBERROR_PARSE;
		auto BADDR = [](auto bptr) { return bptr << 2; };
		auto BSTR = [](auto bstr) { return std::string(reinterpret_cast<char*>(bstr) + 1, bstr[0]); };
		// from debug.cpp@show_exec_tasks
		auto execbase = get_long_debug(4);
		auto ThisTask = get_long_debug(execbase + 276);
		if (ThisTask) {
			auto ln_Name = reinterpret_cast<char*>(get_real_address_debug(get_long_debug(ThisTask + 10)));
			barto_log("GDBSERVER: ln_Name = %s\n", ln_Name);
			auto ln_Type = get_byte_debug(ThisTask + 8);
			bool process = ln_Type == 13; // NT_PROCESS
			sections.clear();
			if (process) {
				constexpr auto sizeofLN = 14;
				// not correct when started from CLI
				auto tc_SPLower = get_long_debug(ThisTask + sizeofLN + 44);
				auto tc_SPUpper = get_long_debug(ThisTask + sizeofLN + 48) - 2;
				stackLower = tc_SPLower;
				stackUpper = tc_SPUpper;
				//auto pr_StackBase = BADDR(get_long_debug(ThisTask + 144));
				//stackUpper = pr_StackBase;

				systemStackLower = get_long_debug(execbase + 58);
				systemStackUpper = get_long_debug(execbase + 54);
				auto pr_SegList = BADDR(get_long_debug(ThisTask + 128));
				// not correct when started from CLI
				auto numSegLists = get_long_debug(pr_SegList + 0);
				auto segList = BADDR(get_long_debug(pr_SegList + 12)); // from debug.cpp@debug()
				auto pr_CLI = BADDR(get_long_debug(ThisTask + 172));
				int pr_TaskNum = get_long_debug(ThisTask + 140);
				if (pr_CLI && pr_TaskNum) {
					auto cli_CommandName = BSTR(get_real_address_debug(BADDR(get_long_debug(pr_CLI + 16))));
					barto_log("GDBSERVER: cli_CommandName = %s\n", cli_CommandName.c_str());
					segList = BADDR(get_long_debug(pr_CLI + 60));
					// don't know how to get the real stack except reading current stack pointer
					auto pr_StackSize = get_long_debug(ThisTask + 132);
					stackUpper = m68k_areg(regs, A7 - A0);
					stackLower = stackUpper - pr_StackSize;
				}
				baseText = 0;
				for (int i = 0; segList; i++) {
					auto size = get_long_debug(segList - 4) - 4;
					auto base = segList + 4;
					if (i == 0) {
						baseText = base;
						sizeText = size;
					}
					if (i == 0)
						response = "$";
					else
						response += ";";
					// this is non-standard (we report addresses of all segments), works only with modified gdb
					response += hex32(base);
					sections.push_back(base);
					barto_log("GDBSERVER:   base=%x; size=%x\n", base, size);
					segList = BADDR(get_long_debug(segList));
				}
			}
		}
		return response;
	}

	std::string handle_qrcmd(const std::string& request) {
		// "monitor" command. used for profiling
		auto cmd = from_hex(request.substr(strlen("qRcmd,")));
		barto_log("GDBSERVER:   monitor %s\n", cmd.c_str());
		// syntax: monitor profile <num_frames> <unwind_file> <out_file>
		if(cmd.substr(0, strlen("profile")) == "profile") {
			auto s = cmd.substr(strlen("profile "));
			std::string profile_unwindname;
			profile_num_frames = 0;
			profile_outname.clear();

			// get num_frames
			while(s[0] >= '0' && s[0] <= '9') {
				profile_num_frames = profile_num_frames * 10 + s[0] - '0';
				s = s.substr(1);
			}
			profile_num_frames = max(1, min(100, profile_num_frames));
			s = s.substr(1); // skip space

			// get profile_unwindname
			if(s.substr(0, 1) == "\"") {
				auto last = s.find('\"', 1);
				if(last != std::string::npos) {
					profile_unwindname = s.substr(1, last - 1);
					s = s.substr(last + 1);
				} else {
					s.clear();
				}
			} else {
				auto last = s.find(' ', 1);
				if(last != std::string::npos) {
					profile_unwindname = s.substr(0, last);
					s = s.substr(last);
				} else {
					s.clear();
				}
			}

			s = s.substr(1); // skip space

			// get profile_outname
			if(s.substr(0, 1) == "\"") {
				auto last = s.find('\"', 1);
				if(last != std::string::npos) {
					profile_outname = s.substr(1, last - 1);
					s = s.substr(last + 1);
				} else {
					s.clear();
				}
			} else {
				profile_outname = s.c_str();
			}

			barto_log("GDBSERVER: profile %d %s %s\n", profile_num_frames, profile_outname.c_str(), profile_unwindname.c_str());

			profile_unwind.reset();
			if(!profile_unwindname.empty()) {
				if(auto f = fopen(profile_unwindname.c_str(), "rb")) {
					profile_unwind = std::make_unique<cpu_profiler_unwind[]>(sizeText >> 1);
					fread(profile_unwind.get(), sizeof(cpu_profiler_unwind), sizeText >> 1, f);
					fclose(f);
				}
			}

			if(!profile_outname.empty()) {
				send_ack(GDB_ACK);
				profile_frame_count = 0;
				debugger_state = state::profile;
				deactivate_debugger();
				return ""; // response is sent when profile is finished (vsync)
			}
		} else if(cmd.substr(0, strlen("console ")) == "console ") {
			std::string cmd_args = cmd.substr(strlen("console "));
			TCHAR *input = const_cast<char*>(cmd_args.c_str());
			barto_log("GDBSERVER: console %s\n", input);
			capture_start();
			debug_line(input);
			TCHAR *output = capture_end();
			return std::string(output, strlen(output));
		} else if(cmd.substr(0, strlen("dumpdma ")) == "dumpdma ") {
			std::string cmd_args = cmd.substr(strlen("dumpdma "));
			if (cmd_args.length() > 0) {
				FILE *dma_outfile = fopen(cmd_args.c_str(), "wb");
				dma_rec *dma_records = get_dma_records(1);
				size_t dma_size = sizeof(dma_rec) * NR_DMA_REC_HPOS * NR_DMA_REC_VPOS;
				barto_log("GDBSERVER: dumpdma %s (%d bytes)\n", cmd_args.c_str(), dma_size);
				fwrite(dma_records, dma_size, 1, dma_outfile);
				return GDB_OK;
			}
		} else if(cmd.substr(0, strlen("screenshot ")) == "screenshot ") {
			std::string cmd_args = cmd.substr(strlen("screenshot "));
			auto frame = uae_fsvideo_getframe();
			// need to flip bits and swap rgb channels
			int w = frame->width;
			int h = frame->height;
			uint8_t *bi_bits = frame->buffer;
			auto bits = std::make_unique<uint8_t[]>(w * 3 * h);
			for(int y = 0; y < h; y++) {
				for(int x = 0; x < w; x++) {
					bits[y * w * 3 + x * 3 + 0] = bi_bits[y * w * 4 + x * 4 + 2];
					bits[y * w * 3 + x * 3 + 1] = bi_bits[y * w * 4 + x * 4 + 1];
					bits[y * w * 3 + x * 3 + 2] = bi_bits[y * w * 4 + x * 4 + 0];
				}
			}
			stbi_write_png(cmd_args.c_str(), w, h, 3, bits.get(), w * 3);
			return GDB_OK;
		} else if(cmd == "reset" && debugging_trigger) {
			savestate_quick(0, 0); // restore state saved at process entry
			barto_debug_resources_count = 0;
			return GDB_OK;
		} else {
			// unknown monitor command
			return GDBERROR_UNSUPPORTED_COMMAND;
		}
		return GDBERROR_PARSE;
	}


	std::string handle_vcont(const std::string& request) {
		std::string response = "";
		auto actions = request.substr(strlen("vCont;"));
		while (!actions.empty()) {
			std::string action;
			// split actions by ';'
			auto semi = actions.find(';');
			if (semi != std::string::npos) {
				action = actions.substr(0, semi);
				actions = actions.substr(semi + 1);
			}
			else {
				action = actions;
				actions.clear();
			}
			// thread specified by ':'
			auto colon = action.find(':');
			int thread_id = THREAD_ID_CPU;
			if (colon != std::string::npos) {
				// parse thread id
				thread_id = strtoul(action.data() + colon + 1, nullptr, 16);
				action = action.substr(0, colon);
			}

			// hmm.. what to do with multiple actions?!

			if (action == "s") { // single-step
				// step over - GDB does this in a different way
				//auto pc = M68K_GETPC;
				//decltype(pc) nextpc;
				//m68k_disasm(pc, &nextpc, pc, 1);
				//trace_mode = TRACE_MATCH_PC;
				//trace_param[0] = nextpc;
				if (thread_id == THREAD_ID_COPPER) {
					// copper step
					debug_copper |= 2;
				}
				else {
					// step in
					trace_param[0] = 1;
					trace_mode = TRACE_SKIP_INS;

					exception_debugging = 1;
					debugger_state = state::connected;
					send_ack(GDB_ACK);
				}
			}
			else if (action == "c") { // continue
				debugger_state = state::connected;
				debug_copper |= 4;
				deactivate_debugger();
				// none work...
				//SetWindowPos(AMonitors[0].hAmigaWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE); // bring window to top
				//BringWindowToTop(AMonitors[0].hAmigaWnd);
				//SetForegroundWindow(AMonitors[0].hAmigaWnd);
				//setmouseactive(0, 2);
				send_ack(GDB_ACK);
			}
			else if (action[0] == 'r') { // keep stepping in range
				auto comma = action.find(',', 2);
				if (comma != std::string::npos) {
					uaecptr start = strtoul(action.data() + 1, nullptr, 16);
					uaecptr end = strtoul(action.data() + comma + 1, nullptr, 16);
					if (thread_id == THREAD_ID_COPPER) {
						// We keep the copper in debug mode to check the breakpoints
						if (start != end) {
							debug_copper |= 8;
						}
						else {
							debug_copper |= 2;
						}
						deactivate_debugger();
					}
					else {
						if (start != end) {
							trace_mode = TRACE_NRANGE_PC;
							trace_param[0] = start;
							trace_param[1] = end;
						}
						else {
							// step over
							uaecptr nextpc = 0;
							uaecptr pc = m68k_getpc();
							// Get the opcode
							uae_u32 opcode = get_word_debug(pc);
							// Check if it is a return opcode
							if (opcode == 0x4e73 			/* RTE */
								|| opcode == 0x4e74 		/* RTD */
								|| opcode == 0x4e75 		/* RTS */
								|| opcode == 0x4e77 		/* RTR */
								|| opcode == 0x4e76 		/* TRAPV */
								//|| (opcode & 0xffc0) == 0x4e80 	/* JSR */
								|| (opcode & 0xffc0) == 0x4ec0 	/* JMP */
								//|| (opcode & 0xff00) == 0x6100	/* BSR */
								|| ((opcode & 0xf000) == 0x6000	/* Bcc */
									&& cctrue((opcode >> 8) & 0xf))
								|| ((opcode & 0xf0f0) == 0x5050	/* DBcc */
									&& !cctrue((opcode >> 8) & 0xf)
									&& (uae_s16)m68k_dreg(regs, opcode & 7) != 0)) {
								// A step to next instruction is needed in this case
								trace_param[0] = 1;
								trace_mode = TRACE_SKIP_INS;
								exception_debugging = 1;
							}
							else {
								// step one instruction after this pc
								m68k_disasm(pc, &nextpc, 0xffffffff, 1);
								trace_mode = TRACE_RANGE_PC;
								trace_param[0] = nextpc;
								trace_param[1] = nextpc + 10;
							}
						}
					}
					debugger_state = state::connected;
					send_ack(GDB_ACK);
				}
			}
			else if (action[0] == 't') { // Pause
				debugger_state = state::debugging;
				activate_debugger();
				stop_signal = "S05";
				response = "S05"; // SIGTRAP
			}
			else {
				barto_log("GDBSERVER: unknown vCont action: %s\n", action.c_str());
				response = GDBERROR_UNSUPPORTED_COMMAND;
			}
		}
		return response;
	}

	std::string handle_set_breakpoint(const std::string& request) {
		std::string response;
		auto comma = request.find(',', strlen("Z0"));
		if (comma != std::string::npos) {
			auto comma_end = request.find(',', 3);
			size_t end_pos = request.size();
			if (comma_end != std::string::npos) {
				end_pos = comma_end;
			}
			auto offset_str = request.substr(3, end_pos - 3);
			uaecptr adr = strtoul(offset_str.data(), nullptr, 16);
			if (adr == 0xffffffff) {
				// step out of kickstart
				trace_mode = TRACE_RANGE_PC;
				trace_param[0] = 0;
				trace_param[1] = 0xF80000;
				response = GDB_OK;
			}
			else {
				// Does the breakpoint exist ?
				for (auto& bpn : bpnodes) {
					if (bpn.enabled && bpn.value1 == adr && bpn.type == BREAKPOINT_REG_PC && bpn.oper == BREAKPOINT_CMP_EQUAL) {
						return GDB_OK;
					}
				}
				// Add the new breakpoint
				response = GDBERROR_MAX_BREAKPOINTS_REACHED;
				for (auto& bpn : bpnodes) {
					if (bpn.enabled)
						continue;
					bpn.value1 = adr;
					bpn.type = BREAKPOINT_REG_PC;
					bpn.oper = BREAKPOINT_CMP_EQUAL;
					bpn.enabled = 1;
					bpn.cnt = 0;
					bpn.chain = -1;
					trace_mode = TRACE_CHECKONLY;
					//print_breakpoints();
					response = GDB_OK;
					break;
				}
				response = GDB_OK;
			}
		}
		else {
			response = GDBERROR_PARSE;
		}
		return response;
	}

	std::string handle_clear_breakpoint(const std::string& request) {
		std::string response;
		auto comma = request.find(',', strlen("z0"));
		if (comma != std::string::npos) {
			uaecptr adr = strtoul(request.data() + strlen("z0,"), nullptr, 16);
			if (adr == 0xffffffff) {
				response = GDB_OK;
			}
			else {
				bool found = false;
				for (auto& bpn : bpnodes) {
					if (bpn.enabled && bpn.value1 == adr) {
						bpn.enabled = 0;
						trace_mode = TRACE_CHECKONLY;
						//print_breakpoints();
						response = GDB_OK;
						found = true;
						break;
					}
				}
				if (!found) {
					barto_log("GDBSERVER: unknown breakpoint at: %x\n", adr);
					print_breakpoints();
					response = GDBERROR_INVALID_BREAKPOINT;
				}
			}
		}
		else {
			response = GDBERROR_PARSE;
		}
		return response;
	}

	std::string handle_set_watchpoint(std::string request) {
		std::string response;
		int rwi = 0;
		if (request[1] == '2')
			rwi = 2; // write
		else if (request[1] == '3')
			rwi = 1; // read
		else
			rwi = 1 | 2; // read + write
		auto comma = request.find(',', strlen("Z2"));
		auto comma2 = request.find(',', strlen("Z2,"));
		if (comma != std::string::npos && comma2 != std::string::npos) {
			uaecptr adr = strtoul(request.data() + strlen("Z2,"), nullptr, 16);
			int size = strtoul(request.data() + comma2 + 1, nullptr, 16);
			barto_log("GDBSERVER: write watchpoint at 0x%x, size 0x%x\n", adr, size);
			bool proceeded = false;
			for (auto& mwn : mwnodes) {
				if (mwn.size)
					continue;
				mwn.addr = adr;
				mwn.size = size;
				mwn.rwi = rwi;
				// defaults from debug.cpp@memwatch()
				mwn.val_enabled = 0;
				mwn.val_mask = 0xffffffff;
				mwn.val = 0;
				mwn.access_mask = MW_MASK_ALL;
				mwn.reg = 0xffffffff;
				mwn.frozen = 0;
				mwn.modval_written = 0;
				mwn.mustchange = 0;
				//mwn.bus_error = 0;
				mwn.reportonly = false;
				mwn.nobreak = false;
				print_watchpoints();
				response += GDB_OK;
				proceeded = true;
				break;
			}
			memwatch_setup();
			if (!proceeded) {
				response = GDBERROR_MAX_BREAKPOINTS_REACHED;
			}
		}
		else {
			response += GDBERROR_PARSE;
		}
		return response;
	}

	std::string handle_clear_watchpoint(const std::string& request) {
		std::string response;
		auto comma = request.find(',', strlen("z2"));
		if (comma != std::string::npos) {
			uaecptr adr = strtoul(request.data() + strlen("z2,"), nullptr, 16);
			bool found = false;
			for (auto& mwn : mwnodes) {
				if (mwn.size && mwn.addr == adr) {
					mwn.size = 0;
					trace_mode = TRACE_CHECKONLY;
					print_watchpoints();
					response = GDB_OK;
					found = true;
					break;
				}
			}
			memwatch_setup();
			if (!found) {
				response = GDBERROR_INVALID_BREAKPOINT;
			}
		}
		else {
			response = GDBERROR_PARSE;
		}
		return response;
	}

	std::string handle_read_memory(const std::string& request) {
		std::string response;
		auto comma = request.find(',');
		if (comma != std::string::npos) {
			std::string mem;
			uaecptr adr = strtoul(request.data() + strlen("m"), nullptr, 16);
			int len = strtoul(request.data() + comma + 1, nullptr, 16);
			barto_log("GDBSERVER: want 0x%x bytes at 0x%x\n", len, adr);
			if ((adr >= 0xdff000) && (adr < 0xdff1fe)) {
				size_t custom_save_length = 0;
				uae_u8* p1 = NULL;
				p1 = save_custom(&custom_save_length, 0, 1);
				if (p1 != NULL) {
					while (len-- > 0) {
						int idx = (adr & 0x1ff) + 4;
						if ((idx > 0) && (idx < custom_save_length)) {
							uae_u8 data = p1[idx];
							mem += hex[data >> 4];
							mem += hex[data & 0xf];
						}
						adr++;
					}
					xfree(p1);
				}
			}
			else {
				while (len-- > 0) {
					auto debug_read_memory_8_no_custom = [](uaecptr addr) -> int {
						addrbank* ad;
						ad = &get_mem_bank(addr);
						if (ad && ad != &custom_bank) {
							return ad->bget(addr);
						}
						return -1;
					};

					auto data = debug_read_memory_8_no_custom(adr);
					if (data == -1) {
						barto_log("GDBSERVER: error reading memory at 0x%x\n", len, adr);
						response = GDBERROR_PROCESSING;
						mem.clear();
						break;
					}
					data &= 0xff; // custom_bget seems to have a problem?
					mem += hex[data >> 4];
					mem += hex[data & 0xf];
					adr++;
				}
			}
			if (mem.length() > 0) {
				response = mem;
			}
		}
		else {
			response = GDBERROR_PARSE;
		}
		return response;
	}

	/**
	 * Finds if it is a safe address or not
	 *
	 * @param addr Address to check
	 * @param size Size of the address
	 * @return true if it is a safe address
	 */
	static bool safe_addr(uaecptr addr, int size)
	{
		addrbank* ab = &get_mem_bank(addr);

		if (!ab)
			return false;

		if (ab->flags & ABFLAG_SAFE)
			return true;

		if (!ab->check(addr, size))
			return false;

		if (ab->flags & (ABFLAG_RAM | ABFLAG_ROM | ABFLAG_ROMIN | ABFLAG_SAFE))
			return true;

		return false;
	}

	/**
	 * Handles a set memory request
	 * `M addr,length:XX`
	 *   Write length addressable memory units starting at address addr (see addressable memory unit). The data is given by XX`; each byte is transmitted as a two-digit hexadecimal number.
	 *   Reply:
	 *   `OK`
	 *       for success
	 *   `E NN`
	 *       for an error (this includes the case where only part of the data was written).
	 */
	static std::string handle_write_memory(const std::string& request) {
		auto comma = request.find(',');
		auto data_pos = request.find(':');
		if ((comma != std::string::npos) && (data_pos != std::string::npos)) {
			data_pos++;
			uaecptr address = strtoul(request.data() + strlen("m"), nullptr, 16);
			int len = strtoul(request.data() + comma + 1, nullptr, 16);
			barto_log("GDBSERVER: want write 0x%x bytes at 0x%x\n", len, address);
			auto mem = from_hex(request.substr(data_pos));
			for (int i = 0; i < mem.length(); i++)
			{
				if (!safe_addr(address, 1)) {
					return GDBERROR_INVALID_MEMORY_LOCATION;
				}
				uae_u8 t = *(mem.data() + i);
				put_byte(address++, t);
			}
		}
		else {
			return GDBERROR_PARSE;
		}
		return GDB_OK;
	}


	/**
	 * Reponse to the qfThreadInfo
	 * Reply:
	 *     `m thread-id`
	 *   A single thread ID
	 *		`m thread-id,thread-id`
	 *   a comma-separated list of thread IDs
	 *		`l`
	 * @param packet Containing the request
	 * @return true if the response was sent without error
	 */
	std::string handle_qfthreadinfo()
	{
		std::string th1 = hex8(THREAD_ID_CPU);
		std::string th2 = hex8(THREAD_ID_COPPER);
		return "m" + th1 + "," + th2;
	}

	/**
	 * Handles a QTFrame command
	 * ! Partial implementation : Not real tracepoint implentation
	 *`QTFrame:n`
	 *   Select the n`th tracepoint frame from the buffer, and use the register and memory contents recorded there to answer subsequent request packets from GDB.
	 *   A successful reply from the stub indicates that the stub has found the requested frame. The response is a series of parts, concatenated without separators, describing the frame we selected. Each part has one of the following forms:
	 *   `F f`
	 *       The selected frame is number n in the trace frame buffer; f is a hexadecimal number. If f is `-1`, then there was no frame matching the criteria in the request packet.
	 *   `T t`
	 *       The selected trace frame records a hit of tracepoint number t; t is a hexadecimal number.
	 * @param request Containing the request
	 * @return true if the response was sent without error
	 */
	std::string handle_qtframe(const std::string& request)
	{
		std::string response;
		int tfnum, tfnum_found;
		struct debugstackframe* tframe;

		tfnum = strtoul(request.data() + strlen("QTFrame:"), nullptr, 16);
		if (tfnum < 0) {
			current_traceframe = DEFAULT_TRACEFRAME;
			response = GDB_OK;
		}
		else {
			tframe = debugmem_find_traceframe(false, tfnum, &tfnum_found);
			if (tframe)
			{
				current_traceframe = tfnum_found;
				if ((tfnum_found < 0) || (tfnum != tfnum_found))
				{
					response = "F-1";
				}
				else
				{
					response = "F" + hex8(tfnum_found) + "T1";
				}
			}
			else
			{
				response = "F-1";
			}
		}
		return response;
	}

	/**
	* `qTStatus`
    Ask the stub if there is a trace experiment running right now.
    The reply has the form:
    `Trunning[;field]`
        running is a single digit 1 if the trace is presently running, or 0 if not. It is followed by semicolon-separated optional fields that an agent may use to report additional status.
    If the trace is not running, the agent may report any of several explanations as one of the optional fields:
    `tnotrun:0`
        No trace has been run yet.
    `tstop[:text]:0`
        The trace was stopped by a user-originated stop command. The optional text field is a user-supplied string supplied as part of the stop command (for instance, an explanation of why the trace was stopped manually). It is hex-encoded.
    `tfull:0`
        The trace stopped because the trace buffer filled up.
    `tdisconnected:0`
        The trace stopped because GDB disconnected from the target.
    `tpasscount:tpnum`
        The trace stopped because tracepoint tpnum exceeded its pass count.
    `terror:text:tpnum`
        The trace stopped because tracepoint tpnum had an error. The string text is available to describe the nature of the error (for instance, a divide by zero in the condition expression); it is hex encoded.
    `tunknown:0`
        The trace stopped for some other reason.
    Additional optional fields supply statistical and other information. Although not required, they are extremely useful for users monitoring the progress of a trace run. If a trace has stopped, and these numbers are reported, they must reflect the state of the just-stopped trace.
    `tframes:n`
        The number of trace frames in the buffer.
    `tcreated:n`
        The total number of trace frames created during the run. This may be larger than the trace frame count, if the buffer is circular.
    `tsize:n`
        The total size of the trace buffer, in bytes.
    `tfree:n`
        The number of bytes still unused in the buffer.
    `circular:n`
        The value of the circular trace buffer flag. 1 means that the trace buffer is circular and old trace frames will be discarded if necessary to make room, 0 means that the trace buffer is linear and may fill up.
    `disconn:n`
        The value of the disconnected tracing flag. 1 means that tracing will continue after GDB disconnects, 0 means that the trace run will stop.
	*/
	std::string handle_qtstatus() {
		std::string tframe_count = hex8(debugmem_get_traceframe_count(false));
		return "T1;tstop::0;tframes:" + tframe_count + ";tcreated:" + tframe_count + ";tfree:ffffff;tsize:50*!;circular:1;disconn:1;starttime:;stoptime:;username:;notes::";
	}

	/**
	 * Handles set breakpoint request for an exception
	 * The message is Z1,0,0;Xf,nnnnnnnnnnnnnnnn
	 *  address is 0 : not used
	 *  One parameter with 16 chars is the 64bit mask for exception filtering
	 * @param packet Packet of the request
	 * @return true if the response was sent without error
	 */
	std::string handle_set_exception_breakpoint(const std::string& request) {
		auto last_comma = request.find_last_of(",");
		if (last_comma != std::string::npos) {
			exception_debugging = 1;
			debug_illegal = 1;
			debug_illegal_mask = strtoul(request.data() + last_comma + 1, nullptr, 16);
			return GDB_OK;
		}
		else {
			return GDBERROR_PARSE;
		}
	}

	/**
	 * Handles set breakpoint request for an exception
	 * The message is z1,0,0;Xf,nnnnnnnnnnnnnnnn
	 *  address is 0 : not used
	 *  One parameter with 16 chars is the 64bit mask for exception filtering
	 * @param packet Packet of the request
	 * @return true if the response was sent without error
	 */
	std::string handle_clear_exception_breakpoint(const std::string& request) {
		exception_debugging = 0;
		debug_illegal = 0;
		debug_illegal_mask = 0;
		return GDB_OK;
	}

	void handle_packet() {
		tracker _;
		if(data_available()) {
			char buf[BUFFER_SIZE];
			auto result = recv(gdbconn, buf, sizeof(buf) - 1, 0);
			if(result > 0) {
				buf[result] = '\0';
				barto_log("GDBSERVER: received %d bytes: >>%s<<\n", result, buf);
				std::string request{ buf }, ack{}, response;
				while(!request.empty() && (request[0] == '+' || request[0] == '-')) {
					if(request[0] == '+') {
						request = request.substr(1);
					} else if(request[0] == '-') {
						barto_log("GDBSERVER: client non-ack'd our last packet\n");
						request = request.substr(1);
					}
				}
				if(!request.empty() && request[0] == 0x03) {
					// Ctrl+C
					ack = "+";
					response = "$";
					response += "S05"; // SIGTRAP
					debugger_state = state::debugging;
					activate_debugger();
				} else if(!request.empty() && request[0] == '$') {
					ack = "-";
					auto end = request.find('#');
					if(end != std::string::npos) {
						uint8_t cksum{};
						for(size_t i = 1; i < end; i++)
							cksum += request[i];
						if(request.length() >= end + 2) {
							if(tolower(request[end + 1]) == hex[cksum >> 4] && tolower(request[end + 2]) == hex[cksum & 0xf]) {
								request = request.substr(1, end - 1);
								barto_log("GDBSERVER: -> %s\n", request.c_str());
								ack = "+";
								response = "$";
								if(request.substr(0, strlen("qSupported")) == "qSupported") {
									response += "PacketSize=";
									response += STRINGIZE(BUFFER_SIZE);
									response += ";BreakpointCommands+;swbreak+;hwbreak+;QStartNoAckMode+;vContSupported+;QTFrame+";
								} else if(request.substr(0, strlen("qAttached")) == "qAttached") {
									response += "1";
								} else if(request.substr(0, strlen("QStartNoAckMode")) == "QStartNoAckMode") {
									send_ack(ack);
									useAck = false;
									response += GDB_OK;
								} else if(request.substr(0, strlen("qfThreadInfo")) == "qfThreadInfo") {
									response += handle_qfthreadinfo();
								} else if(request.substr(0, strlen("qsThreadInfo")) == "qsThreadInfo") {
									response += "l";
								} else if (request.substr(0, strlen("QTFrame")) == "QTFrame") {
									response += handle_qtframe(request);
								} else if (request.substr(0, strlen("QTinit")) == "QTinit") {
									response += GDB_OK;
								} else if (request.substr(0, strlen("QTStop")) == "QTStop") {
									response += GDB_OK;
								} else if (request.substr(0, strlen("QTStart")) == "QTStart") {
									response += GDB_OK;
								} else if (request.substr(0, strlen("qTStatus")) == "qTStatus") {
									response += handle_qtstatus();
								} else if(request.substr(0, strlen("qC")) == "qC") {
									response += "QC1";
								} else if(request.substr(0, strlen("qOffsets")) == "qOffsets") {
									response = handle_qoffsets();
								} else if(request.substr(0, strlen("qRcmd,")) == "qRcmd,") {
									std::string resp = handle_qrcmd(request);
									if (resp.empty()) {
										// No answer, all has been processed in the function
										return;
									}
									response += resp;
								} else if(request.substr(0, strlen("vCont?")) == "vCont?") {
									response += "vCont;c;C;s;S;t;r";
								} else if(request.substr(0, strlen("vCont;")) == "vCont;") {
									std::string resp = handle_vcont(request);
									if (resp.empty()) {
										// No answer, all has been processed in the function
										return;
									}
									response += resp;
								} else if(request[0] == 'H') {
									if (request.substr(0, strlen("Hg")) == "Hg") {
										// getting registers for thread
										int tid = strtoul(request.data() + strlen("Hg"), nullptr, 16);
										response += get_registers(tid);
									}
									else {
										response += GDB_OK;
									}
								} else if(request[0] == 'T') {
									response += GDB_OK;
/*								} else if(request.substr(0, strlen("vRun")) == "vRun") {
									debugger_state = state::wait_for_process;
									activate_debugger();
									send_ack(ack);
									return;
*/								} else if(request[0] == 'D') { // detach
									response += GDB_OK;
/*								} else if(request[0] == '!') { // enable extended mode
									response += GDB_OK;
*/								} else if(request[0] == '?') { // reason for stopping
									response += stop_signal; // SIGTRAP
								} else if(request[0] == 's') { // single-step
									assert(!"should have used vCont;s");
								} else if(request[0] == 'c') { // continue
									assert(!"should have used vCont;c");
								} else if(request[0] == 'k') { // kill
									uae_quit();
									deactivate_debugger();
									return;
								}
								else if (request.substr(0, 2) == "Z0") { // set software breakpoint
									response += handle_set_breakpoint(request);
								}
								else if (request.substr(0, 2) == "z0") { // clear software breakpoint
									response += handle_clear_breakpoint(request);
								}
								else if (request.substr(0, 2) == "Z1") { // set exception breakpoint
									response += handle_set_exception_breakpoint(request);
								}
								else if (request.substr(0, 2) == "z1") { // clear exception breakpoint
									response += handle_clear_exception_breakpoint(request);
								}
								else if (request.substr(0, 2) == "Z2" || request.substr(0, 2) == "Z3" || request.substr(0, 2) == "Z4") { // Z2: write watchpoint, Z3: read watchpoint, Z4: access watchpoint
									response += handle_set_watchpoint(request);
								}
								else if (request.substr(0, 2) == "z2" || request.substr(0, 2) == "z3" || request.substr(0, 2) == "z4") { // Z2: clear write watchpoint, Z3: clear read watchpoint, Z4: clear access watchpoint
									response += handle_clear_watchpoint(request);
								}
								else if (request[0] == 'g') { // get registers
									response += get_registers(THREAD_ID_CPU);
								}
								else if (request[0] == 'p') { // get register
									response += get_register(strtoul(request.data() + 1, nullptr, 16));
								}
								else if (request[0] == 'P') { // write register
									response += set_register(request.data());
								}
								else if (request[0] == 'm') { // read memory
									response += handle_read_memory(request);
								}
								else if (request[0] == 'M') { // read memory
									response += handle_write_memory(request);
								} else {
									response += "E01";
								}
							} else
								barto_log("GDBSERVER: packet checksum mismatch: got %c%c, want %c%c\n", tolower(request[end + 1]), tolower(request[end + 2]), hex[cksum >> 4], hex[cksum & 0xf]);
						} else
							barto_log("GDBSERVER: packet checksum missing\n");
					} else
						barto_log("GDBSERVER: packet end marker '#' not found\n");
				}

				send_ack(ack);
				send_response(response);
			} else if(result == 0) {
				disconnect();
			} else {
				barto_log(_T("GDBSERVER: error receiving data: %d\n"), sock_err);
				disconnect();
			}
		}
		if(!is_connected()) {
			debugger_state = state::inited;
			close();
			deactivate_debugger();
		}
	}

	// called during pause_emulation
	void vsync() {
		if(!enabled) // "gdbserver"
			return;

		// continue emulation if receiving debug commands
		if(debugger_state == state::connected && data_available()) {
			fsemu_action_process_command_in_main(FSEMU_ACTION_PAUSE, 0);
			// handle_packet will be called in next call to vsync_pre
		}
	}

	void vsync_pre() {
		if(!enabled) // "gdbserver"
			return;

		static uae_u32 profile_start_cycles{};
		static size_t profile_custom_regs_size{};
		static uae_u8* profile_custom_regs{}; // at start of profile 
		static size_t profile_custom_agacolors_size{};
		static uae_u8* profile_custom_agacolors{};
		static FILE* profile_outfile{};

		if(debugger_state == state::profile) {
start_profile:
			// start profiling
			barto_log("PRF: %d/%d\n", profile_frame_count + 1, profile_num_frames);
			if(profile_frame_count == 0) {
				profile_outfile = fopen(profile_outname.c_str(), "wb");
				if(!profile_outfile) {
					send_response("$E01");
					debugger_state = state::debugging;
					activate_debugger();
					return;
				}
				int section_count = (int)sections.size();
				fwrite(&profile_num_frames, sizeof(int), 1, profile_outfile);
				fwrite(&section_count, sizeof(int), 1, profile_outfile);
				fwrite(sections.data(), sizeof(uint32_t), section_count, profile_outfile);
				fwrite(&systemStackLower, sizeof(uint32_t), 1, profile_outfile);
				fwrite(&systemStackUpper, sizeof(uint32_t), 1, profile_outfile);
				fwrite(&stackLower, sizeof(uint32_t), 1, profile_outfile);
				fwrite(&stackUpper, sizeof(uint32_t), 1, profile_outfile);

				// store chipmem
				auto profile_chipmem_size = chipmem_bank.reserved_size;
				auto profile_chipmem = std::make_unique<uint8_t[]>(profile_chipmem_size);
				memcpy(profile_chipmem.get(), chipmem_bank.baseaddr, profile_chipmem_size);

				// store bogomem
				auto profile_bogomem_size = bogomem_bank.reserved_size;
				auto profile_bogomem = std::make_unique<uint8_t[]>(profile_bogomem_size);
				memcpy(profile_bogomem.get(), bogomem_bank.baseaddr, profile_bogomem_size);

				// kickstart
				// from memory.cpp@save_rom()
				auto kick_start = 0xf80000;
				auto kick_real_start = kickmem_bank.baseaddr;
				auto kick_size = kickmem_bank.reserved_size;
				// 256KB or 512KB ROM?
				int i;
				for(i = 0; i < kick_size / 2 - 4; i++) {
					if(get_long_debug(i + kick_start) != get_long_debug(i + kick_start + kick_size / 2))
						break;
				}
				if(i == kick_size / 2 - 4) {
					kick_size /= 2;
					kick_start += ROM_SIZE_256;
				}

				fwrite(&kick_size, sizeof(kick_size), 1, profile_outfile);
				fwrite(kick_real_start, 1, kick_size, profile_outfile);

				// memory
				fwrite(&profile_chipmem_size, sizeof(profile_chipmem_size), 1, profile_outfile);
				fwrite(profile_chipmem.get(), 1, profile_chipmem_size, profile_outfile);
				fwrite(&profile_bogomem_size, sizeof(profile_bogomem_size), 1, profile_outfile);
				fwrite(profile_bogomem.get(), 1, profile_bogomem_size, profile_outfile);

				// CPU information
				fwrite(&baseclock, sizeof(int), 1, profile_outfile);
				fwrite(&cpucycleunit, sizeof(int), 1, profile_outfile);
			}

			// store custom registers
			profile_custom_regs = save_custom(&profile_custom_regs_size, nullptr, TRUE);
			profile_custom_agacolors = save_custom_agacolors(&profile_custom_agacolors_size, nullptr);

			// reset idle
			if(barto_debug_idle_count > 0) {
				barto_debug_idle[0] = barto_debug_idle[barto_debug_idle_count - 1] & 0x80000000;
				barto_debug_idle_count = 1;
			}

			// start profiler
			start_cpu_profiler(baseText, baseText + sizeText, profile_unwind.get());
			debug_dma = 1;
			profile_start_cycles = static_cast<uae_u32>(get_cycles() / cpucycleunit);
			//barto_log("GDBSERVER: Start CPU Profiler @ %u cycles\n", get_cycles() / cpucycleunit);
			debugger_state = state::profiling;
		} else if(debugger_state == state::profiling) {
			profile_frame_count++;
			// end profiling
			stop_cpu_profiler();
			debug_dma = 0;
			uae_u32 profile_end_cycles = static_cast<uae_u32>(get_cycles() / cpucycleunit);
			//barto_log("GDBSERVER: Stop CPU Profiler @ %u cycles => %u cycles\n", profile_end_cycles, profile_end_cycles - profile_start_cycles);

			// process dma records
			static constexpr int NR_DMA_REC_HPOS_IN = 256, NR_DMA_REC_VPOS_IN = 1000;
			static constexpr int NR_DMA_REC_HPOS_OUT = 227, NR_DMA_REC_VPOS_OUT = 313;
			auto dma_in = get_dma_records(0);
			auto dma_out = std::make_unique<dma_rec[]>(NR_DMA_REC_HPOS_OUT * NR_DMA_REC_VPOS_OUT);
			for(size_t y = 0; y < NR_DMA_REC_VPOS_OUT; y++) {
				for(size_t x = 0; x < NR_DMA_REC_HPOS_OUT; x++) {
					dma_out[y * NR_DMA_REC_HPOS_OUT + x] = dma_in[y * NR_DMA_REC_HPOS_IN + x];
				}
			}

			int profile_cycles = profile_end_cycles - profile_start_cycles;

			// calculate idle cycles
			int idle_cycles = 0;
			int last_idle = 0;
			for(int i = 0; i < barto_debug_idle_count; i++) {
				auto this_idle = barto_debug_idle[i];
				if((last_idle & 0x80000000) && !(this_idle & 0x80000000)) { // idle->busy
					idle_cycles += (this_idle & 0x7fffffff) - max(profile_start_cycles, (last_idle & 0x7fffffff));
				}

				if((this_idle ^ last_idle) & 0x80000000)
					last_idle = this_idle;
			}
			if(last_idle & 0x80000000)
				idle_cycles += profile_end_cycles - max(profile_start_cycles, (last_idle & 0x7fffffff));
			//barto_log("idle_cycles: %d\n", idle_cycles);

			// Custom Regs
			int custom_len = (int)profile_custom_regs_size;
			fwrite(&custom_len, sizeof(int), 1, profile_outfile);
			fwrite(profile_custom_regs, 1, custom_len, profile_outfile);
			free(profile_custom_regs);
			profile_custom_regs = nullptr;

			// AGA colors
			int custom_agacolors_len = (int)profile_custom_agacolors_size;
			fwrite(&custom_agacolors_len, sizeof(int), 1, profile_outfile);
			if(profile_custom_agacolors) {
				fwrite(profile_custom_agacolors, 1, custom_agacolors_len, profile_outfile);
				free(profile_custom_agacolors);
			}
			profile_custom_agacolors = nullptr;

			// DMA
			int dmarec_size = sizeof(dma_rec);
			int dmarec_count = NR_DMA_REC_HPOS_OUT * NR_DMA_REC_VPOS_OUT;
			fwrite(&dmarec_size, sizeof(int), 1, profile_outfile);
			fwrite(&dmarec_count, sizeof(int), 1, profile_outfile);
			fwrite(dma_out.get(), sizeof(dma_rec), NR_DMA_REC_HPOS_OUT * NR_DMA_REC_VPOS_OUT, profile_outfile);

			// resources
			int resource_size = sizeof(barto_debug_resource);
			int resource_count = barto_debug_resources_count;
			fwrite(&resource_size, sizeof(int), 1, profile_outfile);
			fwrite(&resource_count, sizeof(int), 1, profile_outfile);
			fwrite(barto_debug_resources, resource_size, resource_count, profile_outfile);

			fwrite(&profile_cycles, sizeof(int), 1, profile_outfile);
			fwrite(&idle_cycles, sizeof(int), 1, profile_outfile);

			// profiles
			int profile_count = get_cpu_profiler_output_count();
			fwrite(&profile_count, sizeof(int), 1, profile_outfile);
			fwrite(get_cpu_profiler_output(), sizeof(uae_u32), profile_count, profile_outfile);
			// write screenshot
			redraw_frame();
			auto frame = uae_fsvideo_getframe();

			// need to flip bits and swap rgb channels
			int w = frame->width;
			int h = frame->height;
			uint8_t *bi_bits = frame->buffer;
			auto bits = std::make_unique<uint8_t[]>(w * 3 * h);
			for(int y = 0; y < h; y++) {
				for(int x = 0; x < w; x++) {
					bits[y * w * 3 + x * 3 + 0] = bi_bits[y * w * 4 + x * 4 + 2];
					bits[y * w * 3 + x * 3 + 1] = bi_bits[y * w * 4 + x * 4 + 1];
					bits[y * w * 3 + x * 3 + 2] = bi_bits[y * w * 4 + x * 4 + 0];
				}
			}
			struct write_context_t {
				uint8_t data[2'000'000]{};
				int size = 0;
				int type = 0;
			};
			auto write_context = std::make_unique<write_context_t>();
			auto write_func = [](void* _context, void* data, int size) {
				auto context = (write_context_t*)_context;
				memcpy(&context->data[context->size], data, size);
				context->size += size;
			};
			if(profile_num_frames > 1) {
				stbi_write_jpg_to_func(write_func, write_context.get(), w, h, 3, bits.get(), 50);
				write_context->type = 0; // JPG
			} else {
				stbi_write_png_to_func(write_func, write_context.get(), w, h, 3, bits.get(), w * 3);
				write_context->type = 1; // PNG
			}
			write_context->size = (write_context->size + 3) & ~3; // pad to 32bit
			fwrite(&write_context->size, sizeof(int), 1, profile_outfile);
			fwrite(&write_context->type, sizeof(int), 1, profile_outfile);
			fwrite(write_context->data, 1, write_context->size, profile_outfile);

			if(profile_frame_count == profile_num_frames) {
				fclose(profile_outfile);
				send_response("$OK");

				debugger_state = state::debugging;
				activate_debugger();
			} else {
				debugger_state = state::profile;
				goto start_profile;
			}
		}

		if(debugger_state == state::connected && data_available()) {
			handle_packet();
		}
	}

	void vsync_post() {
		if(!enabled)
			return;
	}

	uaecptr KPutCharX{};
	uaecptr Trap7{};
	uaecptr AddressError{};
	uaecptr IllegalError{};
	std::string KPutCharOutput;

	void output(const char* string) {
		if(gdbconn != INVALID_SOCKET && !in_handle_packet) {
			std::string response = "$O";
			while(*string)
				response += hex8(*string++);
			send_response(response);
		}
	}

	void log_output(const TCHAR* tstring) {
		std::string utf8(tstring);
		if(utf8.substr(0, 5) == "DBG: ") {
			utf8 = utf8.substr(0, utf8.length() - 1); // get rid of extra newline from uaelib
			for(size_t start = 0;;) { // append "DBG: " to every newline, because GDB splits text by lines and vscode doesn't know that the extra lines are DBG output
				auto p = utf8.find('\n', start);
				if(p == std::string::npos || p == utf8.length() - 1)
					break;

				utf8.replace(p, 1, "\nDBG: ");
				start = p + 6;
			}

		}
		output(utf8.c_str());
	}

	// returns true if gdbserver handles debugging
	bool debug() {
		if(!enabled)
			return false;

		fsemu_action_process_command_in_main(FSEMU_ACTION_WARP, 0);
		//cfgfile_modify(-1, _T("warp false"), 0, nullptr, 0);
		//cfgfile_modify(-1, _T("cpu_speed real"), 0, nullptr, 0);
		//cfgfile_modify(-1, _T("cpu_cycle_exact true"), 0, nullptr, 0);
		//cfgfile_modify(-1, _T("cpu_memory_cycle_exact true"), 0, nullptr, 0);
		//cfgfile_modify(-1, _T("blitter_cycle_exact true"), 0, nullptr, 0);

		// break at start of process
		if(debugger_state == state::inited) {
			if(debugging_trigger) {
				//KPutCharX
				auto execbase = get_long_debug(4);
				KPutCharX = execbase - 0x204;
				for(auto& bpn : bpnodes) {
					if(bpn.enabled)
						continue;
					bpn.value1 = KPutCharX;
					bpn.type = BREAKPOINT_REG_PC;
					bpn.oper = BREAKPOINT_CMP_EQUAL;
					bpn.enabled = 1;
					bpn.cnt = 0;
					bpn.chain = -1;
					barto_log("GDBSERVER: Breakpoint for KPutCharX at 0x%x installed\n", bpn.value1);
					break;
				}

				// TRAP#7 breakpoint (GCC generates this opcode when it encounters undefined behavior)
				Trap7 = get_long_debug(regs.vbr + 0x9c);
				for(auto& bpn : bpnodes) {
					if(bpn.enabled)
						continue;
					bpn.value1 = Trap7;
					bpn.type = BREAKPOINT_REG_PC;
					bpn.oper = BREAKPOINT_CMP_EQUAL;
					bpn.enabled = 1;
					bpn.cnt = 0;
					bpn.chain = -1;
					barto_log("GDBSERVER: Breakpoint for TRAP#7 at 0x%x installed\n", bpn.value1);
					break;
				}

				AddressError = get_long_debug(regs.vbr + 3 * 4);
				for(auto& bpn : bpnodes) {
					if(bpn.enabled)
						continue;
					bpn.value1 = AddressError;
					bpn.type = BREAKPOINT_REG_PC;
					bpn.oper = BREAKPOINT_CMP_EQUAL;
					bpn.enabled = 1;
					bpn.cnt = 0;
					bpn.chain = -1;
					barto_log("GDBSERVER: Breakpoint for AddressError at 0x%x installed\n", bpn.value1);
					break;
				}

				IllegalError = get_long_debug(regs.vbr + 4 * 4);
				for(auto& bpn : bpnodes) {
					if(bpn.enabled)
						continue;
					bpn.value1 = IllegalError;
					bpn.type = BREAKPOINT_REG_PC;
					bpn.oper = BREAKPOINT_CMP_EQUAL;
					bpn.enabled = 1;
					bpn.cnt = 0;
					bpn.chain = -1;
					barto_log("GDBSERVER: Breakpoint for IllegalError at 0x%x installed\n", bpn.value1);
					break;
				}

				// watchpoint for NULL (GCC sees this as undefined behavior)
				// disabled for now, always triggered in OpenScreen()
				/*for(auto& mwn : mwnodes) {
					if(mwn.size)
						continue;
					mwn.addr = 0;
					mwn.size = 4;
					mwn.rwi = 1 | 2; // read + write
					// defaults from debug.cpp@memwatch()
					mwn.val_enabled = 0;
					mwn.val_mask = 0xffffffff;
					mwn.val = 0;
					mwn.access_mask = MW_MASK_CPU_D_R | MW_MASK_CPU_D_W; // CPU data read/write only
					mwn.reg = 0xffffffff;
					mwn.frozen = 0;
					mwn.modval_written = 0;
					mwn.mustchange = 0;
					mwn.bus_error = 0;
					mwn.reportonly = false;
					mwn.nobreak = false;
					memwatch_setup();
					barto_log("GDBSERVER: Watchpoint for NULL installed\n");
					break;
				}*/

				// enable break at exceptions - doesn't break when exceptions occur in Kickstart
				debug_illegal = 1;
				debug_illegal_mask = (1 << 3) | (1 << 4); // 3 = address error, 4 = illegal instruction

				// from debug.cpp@process_breakpoint()
				processptr = 0;
				xfree(processname);
				processname = nullptr;
				savestate_quick(0, 1); // save state for "monitor reset"
			}
			barto_log("GDBSERVER: Waiting for connection...\n");
			for (int i = 0; i < time_out * 10; i++)	{
				if (is_connected()) {
					barto_log("GDBSERVER: connected\n");
					useAck = true;
					debugger_state = state::debugging;
					debugmem_enable_stackframe(true);
					debugmem_trace = true;
					break;
				}
				usleep(100000);
			}
			if (debugger_state != state::debugging) {
				barto_log("GDBSERVER: timed out after %ds\n", time_out);
			}
		}

		// something stopped execution and entered debugger
		if(debugger_state == state::connected) {
//while(!IsDebuggerPresent()) Sleep(100); __debugbreak();
			auto pc = munge24(m68k_getpc());
			if (pc == KPutCharX) {
				// if this is too slow, hook uaelib trap#86
				auto ascii = static_cast<uint8_t>(m68k_dreg(regs, 0));
				KPutCharOutput += ascii;
				if(ascii == '\0') {
					std::string response = "$O";
					for(const auto& ch : KPutCharOutput)
						response += hex8(ch);
					send_response(response);
					KPutCharOutput.clear();
				}
				deactivate_debugger();
				return true;
			}

			std::string response{ "S05" };
			stop_signal = "S05";
			if (debug_copper & 8) {
				// copper debugging
				debug_copper &= ~8;
				response = "T05swbreak:;thread:" + hex8(THREAD_ID_COPPER);
				goto send_response;
			}

			// Check storaged exception code
			if (exception_no > 0) {
				regs.pc = regs.instruction_pc_user_exception;
				m68k_areg(regs, A7 - A0) = regs.usp;

				switch (exception_no) {
					case 2: // Bus error
					case 3: // Address error
						response = "S0A"; // SIGBUS
						break;
					case 4: // Illegal instruction
					case 10: // Unimplemented instruction (line A)
					case 11: // Unimplemented instruction (line F)
						response = "S04"; // SIGILL
						break;
					case 5: // Division by zero
						response = "S08"; // SIGFPE
						break;
					default:
						response = "S02"; // SIGINT
				}
				exception_no = 0;
			}

			//if(memwatch_triggered) // can't use, debug() will reset it, so just check mwhit
			if(mwhit.size) {
				for(const auto& mwn : mwnodes) {
					if(mwn.size && mwhit.addr >= mwn.addr && mwhit.addr < mwn.addr + mwn.size) {
						if(mwn.addr == 0) {
							response = "S0B"; // undefined behavior -> SIGSEGV
						} else {
//while(!IsDebuggerPresent()) Sleep(100); __debugbreak();
//							auto data = get_long_debug(mwn.addr);
							response = "T05";
							if(mwhit.rwi == 2)
								response += "watch";
							else if(mwhit.rwi == 1)
								response += "rwatch";
							else
								response += "awatch";
							response += ":";
							response += hex32(mwhit.addr);
							response += ";";
						}
						// so we don't trigger again
						mwhit.size = 0;
						mwhit.addr = 0;
						goto send_response;
					}
				}
			}
			for(const auto& bpn : bpnodes) {
				if(bpn.enabled && bpn.type == BREAKPOINT_REG_PC && bpn.value1 == pc) {
					// see binutils-gdb/include/gdb/signals.def for number of signals
					if(pc == Trap7) {
						response = "S07"; // TRAP#7 -> SIGEMT
						stop_signal = "S07";
						// unwind PC & stack for better debugging experience (otherwise we're probably just somewhere in Kickstart)
						regs.pc = regs.instruction_pc_user_exception - 2;
						m68k_areg(regs, A7 - A0) = regs.usp;
					} else if(pc == AddressError) {
						response = "S0A"; // AddressError -> SIGBUS
						stop_signal = "S0A";
						// unwind PC & stack for better debugging experience (otherwise we're probably just somewhere in Kickstart)
						regs.pc = regs.instruction_pc_user_exception; // don't know size of opcode that caused exception
						m68k_areg(regs, A7 - A0) = regs.usp;
					} else if(pc == IllegalError) {
						response = "S04"; // AddressError -> SIGILL
						stop_signal = "S04";
						// unwind PC & stack for better debugging experience (otherwise we're probably just somewhere in Kickstart)
						regs.pc = regs.instruction_pc_user_exception; // don't know size of opcode that caused exception
						m68k_areg(regs, A7 - A0) = regs.usp;
					} else {
						response = "T05swbreak:;";
						stop_signal = "S05";
					}
					goto send_response;
				}
			}
send_response:
			send_response("$" + response);
			trace_mode = 0;
			debugger_state = state::debugging;
		}

		// debugger active
		while(debugger_state == state::debugging) {
			handle_packet();

			#ifdef _WIN32
			MSG msg{};
			while(PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			#endif
			Sleep(1);
		}

		return true;
	}

	/**
	 * Main function that will be called when doing the copper debugging
	 */
	bool remote_debug_copper(uaecptr addr, uae_u16 word1, uae_u16 word2, int hpos, int vpos)
	{
		// scan breakpoints for the current address
		if (debug_copper & 4) {
			// check breakpoints for copper
			for (int i = 0; i < BREAKPOINT_TOTAL; i++) {
				struct breakpoint_node* bpn = &bpnodes[i];
				if (bpn->enabled && (bpn->type == BREAKPOINT_REG_PC)) {
					int tested_copper_pc = bpn->value1;
					if (addr >= tested_copper_pc && addr <= tested_copper_pc + 3) {
						debugger_state = state::connected;
						debug_copper |= 8;
						activate_debugger_new();
						return true;
					}
				}
			}
		}
		if (debug_copper & 2) {
			debugger_state = state::connected;
			debug_copper &= ~2;
			debug_copper |= 8;
			activate_debugger_new();
			return true;
		}
		return false;
	}
} // namespace barto_gdbserver
