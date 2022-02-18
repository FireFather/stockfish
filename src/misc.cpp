/*
  Stockfish, a UCI chess playing engine derived from Glaurung 2.1
  Copyright (C) 2004-2022 The Stockfish developers (see AUTHORS file)

  Stockfish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Stockfish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
// The needed Windows API for processor groups could be missed from old Windows
// versions, so instead of calling them directly (forcing the linker to resolve
// the calls at compile time), try to load them at runtime. To do this we need
// first to define the corresponding function pointers.
extern "C" {
	typedef bool(*fun1_t)(LOGICAL_PROCESSOR_RELATIONSHIP,
		PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD);
	typedef bool(*fun2_t)(USHORT, PGROUP_AFFINITY);
	typedef bool(*fun3_t)(HANDLE, CONST GROUP_AFFINITY*, PGROUP_AFFINITY);
	typedef bool(*fun4_t)(USHORT, PGROUP_AFFINITY, USHORT, PUSHORT);
	typedef WORD(*fun5_t)();
}
#endif

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <cstdlib>

#if defined(__linux__) && !defined(__ANDROID__)
#include <stdlib.h>
#include <sys/mman.h>
#endif

#if defined(__APPLE__) || defined(__ANDROID__) || defined(__OpenBSD__) || (defined(__GLIBCXX__) && !defined(_GLIBCXX_HAVE_ALIGNED_ALLOC) && !defined(_WIN32)) || defined(__e2k__)
#define POSIXALIGNEDALLOC
#include <stdlib.h>
#endif

#include "misc.h"
#include "thread.h"

using namespace std;

namespace Stockfish {

	namespace {

		/// Version number. If Version is left empty, then compile date in the format
		/// DD-MM-YY and show in engine_info.
		const string Version;
		bool LPMessage = false;
	} // namespace

	/// engine_info() returns the full name of the current Stockfish version. This
	/// will be either "Stockfish <Tag> DD-MM-YY" (where DD-MM-YY is the date when
	/// the program was compiled) or "Stockfish <Version>", depending on whether
	/// Version is empty.

	string engine_info(bool to_uci) {

		const string months("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec");
		string month, day, year;
		stringstream ss, date(__DATE__); // From compiler, format is "Sep 21 2008"

		ss << "Stockfish " << Version << setfill('0');

		if (Version.empty())
		{
			date >> month >> day >> year;
			ss << setw(2) << day << setw(2) << (1 + months.find(month) / 4) << year.substr(2);
		}

		ss << (to_uci ? "\nid author " : " by ")
			<< "the Stockfish developers (see AUTHORS file)";

		if (!to_uci)
		{
			date >> month >> day >> year;

			ss << "\n"
				<< compiler_info()
				<< "\nBuild date/time  : " << year << '-' << setw(2) << setfill('0') << month << '-' << setw(2) << setfill('0') << day << ' ' << __TIME__
				<< "\n";
		}

		return ss.str();
	}


	/// compiler_info() returns a string trying to describe the compiler we use

	std::string compiler_info() {

#define stringify2(x) #x
#define stringify(x) stringify2(x)
#define make_version_string(major, minor, patch) stringify(major) "." stringify(minor) "." stringify(patch)

		/// Predefined macros hell:
		///
		/// __GNUC__           Compiler is gcc, Clang or Intel on Linux
		/// __INTEL_COMPILER   Compiler is Intel
		/// _MSC_VER           Compiler is MSVC or Intel on Windows
		/// _WIN32             Building on Windows (any)
		/// _WIN64             Building on Windows 64 bit

		std::string compiler = "\nCompiled using   : ";

#ifdef __clang__
		compiler += "clang++ ";
		compiler += make_version_string(__clang_major__, __clang_minor__, __clang_patchlevel__);
#elif __INTEL_COMPILER
		compiler += "Intel compiler ";
		compiler += "(version ";
		compiler += stringify(__INTEL_COMPILER) " update " stringify(__INTEL_COMPILER_UPDATE);
		compiler += ")";
#elif _MSC_VER
		compiler += "MSVC ";
		compiler += "(version ";
		compiler += stringify(_MSC_FULL_VER) "." stringify(_MSC_BUILD);
		compiler += ")";
#elif defined(__e2k__) && defined(__LCC__)
#define dot_ver2(n) \
      compiler += (char)'.'; \
      compiler += (char)('0' + (n) / 10); \
      compiler += (char)('0' + (n) % 10);

		compiler += "MCST LCC ";
		compiler += "(version ";
		compiler += std::to_string(__LCC__ / 100);
		dot_ver2(__LCC__ % 100)
			dot_ver2(__LCC_MINOR__)
			compiler += ")";
#elif __GNUC__
		compiler += "g++ (GNUC) ";
		compiler += make_version_string(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
		compiler += "Unknown compiler ";
		compiler += "(unknown version)";
#endif

#if defined(__APPLE__)
		compiler += " on Apple";
#elif defined(__CYGWIN__)
		compiler += " on Cygwin";
#elif defined(__MINGW64__)
		compiler += " on MinGW64";
#elif defined(__MINGW32__)
		compiler += " on MinGW32";
#elif defined(__ANDROID__)
		compiler += " on Android";
#elif defined(__linux__)
		compiler += " on Linux";
#elif defined(_WIN64)
		compiler += " on Microsoft Windows 64-bit";
#elif defined(_WIN32)
		compiler += " on Microsoft Windows 32-bit";
#else
		compiler += " on unknown system";
#endif

		compiler += "\nCompilation settings include: ";
		compiler += (Is64Bit ? " 64bit" : " 32bit");
#if defined(USE_VNNI)
		compiler += " VNNI";
#endif
#if defined(USE_AVX512)
		compiler += " AVX512";
#endif
		compiler += (HasPext ? " BMI2" : "");
#if defined(USE_AVX2)
		compiler += " AVX2";
#endif
#if defined(USE_SSE41)
		compiler += " SSE41";
#endif
#if defined(USE_SSSE3)
		compiler += " SSSE3";
#endif
#if defined(USE_SSE2)
		compiler += " SSE2";
#endif
		compiler += (HasPopCnt ? " POPCNT" : "");
#if defined(USE_MMX)
		compiler += " MMX";
#endif
#if defined(USE_NEON)
		compiler += " NEON";
#endif

#if !defined(NDEBUG)
		compiler += " DEBUG";
#endif

		return compiler;
	}


	/// Debug functions used mainly to collect run-time statistics
	static std::atomic<int64_t> hits[2], means[2];

	void dbg_hit_on(const bool b) { ++hits[0]; if (b) ++hits[1]; }
	void dbg_hit_on(const bool c, const bool b) { if (c) dbg_hit_on(b); }
	void dbg_mean_of(const int v) { ++means[0]; means[1] += v; }

	void dbg_print() {

		if (hits[0])
			cerr << "Total " << hits[0] << " Hits " << hits[1]
			<< " hit rate (%) " << 100 * hits[1] / hits[0] << endl;

		if (means[0])
			cerr << "Total " << means[0] << " Mean "
			<< static_cast<double>(means[1]) / means[0] << endl;
	}


	/// Used to serialize access to std::cout to avoid multiple threads writing at
	/// the same time.

	std::ostream& operator<<(std::ostream& os, const SyncCout sc) {

		static std::mutex m;

		if (sc == IO_LOCK)
			m.lock();

		if (sc == IO_UNLOCK)
			m.unlock();

		return os;
	}


	/// prefetch() preloads the given address in L1/L2 cache. This is a non-blocking
	/// function that doesn't stall the CPU waiting for data to be loaded from memory,
	/// which can be quite slow.
#ifdef NO_PREFETCH

	void prefetch(void*) {}

#else

	void prefetch(void* addr) {

#  if defined(__INTEL_COMPILER)
		// This hack prevents prefetches from being optimized away by
		// Intel compiler. Both MSVC and gcc seem not be affected by this.
		__asm__("");
#  endif

#  if defined(__INTEL_COMPILER) || defined(_MSC_VER)
		_mm_prefetch(static_cast<char*>(addr), _MM_HINT_T0);
#  else
		__builtin_prefetch(addr);
#  endif
	}

#endif


	/// std_aligned_alloc() is our wrapper for systems where the c++17 implementation
	/// does not guarantee the availability of aligned_alloc(). Memory allocated with
	/// std_aligned_alloc() must be freed with std_aligned_free().

	void* std_aligned_alloc(const size_t alignment, const size_t size) {

#if defined(POSIXALIGNEDALLOC)
		void* mem;
		return posix_memalign(&mem, alignment, size) ? nullptr : mem;
#elif defined(_WIN32)
		return _mm_malloc(size, alignment);
#else
		return std::aligned_alloc(alignment, size);
#endif
	}

	void std_aligned_free(void* ptr) {

#if defined(POSIXALIGNEDALLOC)
		free(ptr);
#elif defined(_WIN32)
		_mm_free(ptr);
#else
		free(ptr);
#endif
	}

	/// aligned_large_pages_alloc() will return suitably aligned memory, if possible using large pages.

#if defined(_WIN32)

	static void* aligned_large_pages_alloc_windows(size_t allocSize) {

#if !defined(_WIN64)
		(void)allocSize; // suppress unused-parameter compiler warning
		return nullptr;
#else

		HANDLE hProcessToken{ };
		LUID luid{ };
		void* mem = nullptr;

		const size_t largePageSize = GetLargePageMinimum();
		if (!largePageSize)
			return nullptr;

		// We need SeLockMemoryPrivilege, so try to enable it for the process
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken))
			return nullptr;

		if (LookupPrivilegeValue(nullptr, SE_LOCK_MEMORY_NAME, &luid))
		{
			TOKEN_PRIVILEGES tp{ };
			TOKEN_PRIVILEGES prevTp{ };
			DWORD prevTpLen = 0;

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			// Try to enable SeLockMemoryPrivilege. Note that even if AdjustTokenPrivileges() succeeds,
			// we still need to query GetLastError() to ensure that the privileges were actually obtained.
			if (AdjustTokenPrivileges(
				hProcessToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &prevTp, &prevTpLen) &&
				GetLastError() == ERROR_SUCCESS)
			{
				// Round up size to full pages and allocate
				allocSize = (allocSize + largePageSize - 1) & ~(largePageSize - 1);
				mem = VirtualAlloc(
					nullptr, allocSize, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);

				// Privilege no longer needed, restore previous state
				AdjustTokenPrivileges(hProcessToken, FALSE, &prevTp, 0, nullptr, nullptr);
			}
		}

		CloseHandle(hProcessToken);

		return mem;

#endif
	}

	void* aligned_large_pages_alloc(const size_t size) {

		// Try to allocate large pages
		void* mem = aligned_large_pages_alloc_windows(size);

		// Fall back to regular, page aligned, allocation if necessary
  if (!mem)
        {
        mem = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	    if (LPMessage == false)
		    {
		    cout << "Large Pages      : No" << endl << endl;
		    LPMessage = true;
            }
        }
  else
        {
	    if (LPMessage == false)
		    {
		    cout << "Large Pages      : Yes" << endl << endl;
		    LPMessage = true;
            }
	    }
  return mem;
	}

#else

	void* aligned_large_pages_alloc(size_t allocSize) {

#if defined(__linux__)
		constexpr size_t alignment = 2 * 1024 * 1024; // assumed 2MB page size
#else
		constexpr size_t alignment = 4096; // assumed small page size
#endif

  // round up to multiples of alignment
		size_t size = ((allocSize + alignment - 1) / alignment) * alignment;
		void* mem = std_aligned_alloc(alignment, size);
#if defined(MADV_HUGEPAGE)
		madvise(mem, size, MADV_HUGEPAGE);
#endif
		if (mem)
		{
			if (LPMessage == false)
			{
				cout << "Huge Pages      : Yes" << endl << endl;
				LPMessage = true;
			}
		}
		else
		{
			if (LPMessage == false)
			{
				cout << "Huge Pages      : No" << endl << endl;
				LPMessage = true;
			}
		}
		return mem;
	}

#endif


	/// aligned_large_pages_free() will free the previously allocated ttmem

#if defined(_WIN32)

	void aligned_large_pages_free(void* mem) {

		if (mem && !VirtualFree(mem, 0, MEM_RELEASE))
		{
			const DWORD err = GetLastError();
			std::cerr << "Failed to free large page memory. Error code: 0x"
				<< std::hex << err
				<< std::dec << std::endl;
			exit(EXIT_FAILURE);
		}
	}

#else

	void aligned_large_pages_free(void* mem) {
		std_aligned_free(mem);
	}

#endif


	namespace WinProcGroup {

#ifndef _WIN32

		void bindThisThread(size_t) {}

#else

		/// best_node() retrieves logical processor information using Windows specific
		/// API and returns the best node id for the thread with index idx. Original
		/// code from Texel by Peter Österlund.

		int best_node(const size_t idx) {

			int threads = 0;
			int nodes = 0;
			int cores = 0;
			DWORD returnLength = 0;
			DWORD byteOffset = 0;

			// Early exit if the needed API is not available at runtime
			const HMODULE k32 = GetModuleHandle("Kernel32.dll");
			const auto fun1 = reinterpret_cast<fun1_t>(reinterpret_cast<void(*)()>(GetProcAddress(k32, "GetLogicalProcessorInformationEx")));
			if (!fun1)
				return -1;

			// First call to GetLogicalProcessorInformationEx() to get returnLength.
			// We expect the call to fail due to null buffer.
			if (fun1(RelationAll, nullptr, &returnLength))
				return -1;

			// Once we know returnLength, allocate the buffer
			SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* buffer;
			SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* ptr = buffer = static_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(malloc(returnLength));

			// Second call to GetLogicalProcessorInformationEx(), now we expect to succeed
			if (!fun1(RelationAll, buffer, &returnLength))
			{
				free(buffer);
				return -1;
			}

			while (byteOffset < returnLength)
			{
				if (ptr->Relationship == RelationNumaNode)
					nodes++;

				else if (ptr->Relationship == RelationProcessorCore)
				{
					cores++;
					threads += (ptr->Processor.Flags == LTP_PC_SMT) ? 2 : 1;
				}

				assert(ptr->Size);
				byteOffset += ptr->Size;
				ptr = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(reinterpret_cast<char*>(ptr) + ptr->Size);
			}

			free(buffer);

			std::vector<int> groups;

			// Run as many threads as possible on the same node until core limit is
			// reached, then move on filling the next node.
			for (int n = 0; n < nodes; n++)
				for (int i = 0; i < cores / nodes; i++)
					groups.push_back(n);

			// In case a core has more than one logical processor (we assume 2) and we
			// have still threads to allocate, then spread them evenly across available
			// nodes.
			for (int t = 0; t < threads - cores; t++)
				groups.push_back(t % nodes);

			// If we still have more threads than the total number of logical processors
			// then return -1 and let the OS to decide what to do.
			return idx < groups.size() ? groups[idx] : -1;
		}


		/// bindThisThread() set the group affinity of the current thread

		void bindThisThread(const size_t idx) {

			// Use only local variables to be thread-safe
			const int node = best_node(idx);

			if (node == -1)
				return;

			// Early exit if the needed API are not available at runtime
			const HMODULE k32 = GetModuleHandle("Kernel32.dll");
			const auto fun2 = reinterpret_cast<fun2_t>(reinterpret_cast<void(*)()>(GetProcAddress(k32, "GetNumaNodeProcessorMaskEx")));
			const auto fun3 = reinterpret_cast<fun3_t>(reinterpret_cast<void(*)()>(GetProcAddress(k32, "SetThreadGroupAffinity")));
			const auto fun4 = reinterpret_cast<fun4_t>(reinterpret_cast<void(*)()>(GetProcAddress(k32, "GetNumaNodeProcessorMask2")));
			const auto fun5 = reinterpret_cast<fun5_t>(reinterpret_cast<void(*)()>(GetProcAddress(k32, "GetMaximumProcessorGroupCount")));

			if (!fun2 || !fun3)
				return;

			if (!fun4 || !fun5)
			{
				GROUP_AFFINITY affinity;
				if (fun2(node, &affinity))                                                 // GetNumaNodeProcessorMaskEx
					fun3(GetCurrentThread(), &affinity, nullptr);                          // SetThreadGroupAffinity
			}
			else
			{
				// If a numa node has more than one processor group, we assume they are
				// sized equal and we spread threads evenly across the groups.
				USHORT returnedElements;
				const USHORT elements = fun5();                                                         // GetMaximumProcessorGroupCount
				auto* affinity = static_cast<GROUP_AFFINITY*>(malloc(elements * sizeof(GROUP_AFFINITY)));
				if (fun4(node, affinity, elements, &returnedElements))                     // GetNumaNodeProcessorMask2
					fun3(GetCurrentThread(), &affinity[idx % returnedElements], nullptr);  // SetThreadGroupAffinity
				free(affinity);
			}
		}

#endif

	} // namespace WinProcGroup

#ifdef _WIN32
#include <direct.h>
#define GETCWD _getcwd
#else
#include <unistd.h>
#define GETCWD getcwd
#endif

	namespace CommandLine {

		string argv0;            // path+name of the executable binary, as given by argv[0]
		string binaryDirectory;  // path of the executable directory
		string workingDirectory; // path of the working directory

		void init(const int argc, char* argv[]) {
			(void)argc;
			string pathSeparator;

			// extract the path+name of the executable binary
			argv0 = argv[0];

#ifdef _WIN32
			pathSeparator = "\\";
#ifdef _MSC_VER
			// Under windows argv[0] may not have the extension. Also _get_pgmptr() had
			// issues in some windows 10 versions, so check returned values carefully.
			char* pgmptr = nullptr;
			if (!_get_pgmptr(&pgmptr) && pgmptr != nullptr && *pgmptr)
				argv0 = pgmptr;
#endif
#else
			pathSeparator = "/";
#endif

			// extract the working directory
			workingDirectory = "";
			char buff[40000];
			if (const char* cwd = GETCWD(buff, 40000))
				workingDirectory = cwd;

			// extract the binary directory path from argv0
			binaryDirectory = argv0;
			if (const size_t pos = binaryDirectory.find_last_of("\\/"); pos == std::string::npos)
				binaryDirectory = "." + pathSeparator;
			else
				binaryDirectory.resize(pos + 1);

			// pattern replacement: "./" at the start of path is replaced by the working directory
			if (binaryDirectory.find("." + pathSeparator) == 0)
				binaryDirectory.replace(0, 1, workingDirectory);
		}


	} // namespace CommandLine

} // namespace Stockfish
