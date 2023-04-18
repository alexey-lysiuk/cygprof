
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <atomic>
#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

#include <dlfcn.h>

struct CygHeader
{
	uint32_t magic;
	uint32_t version;
	uint32_t symbols;
};

struct CygEvent
{
	void* address;
	uint64_t stamp;
};

static std::atomic<bool> initialized;
static std::vector<CygEvent> events;

using namespace std::chrono;
const auto start = steady_clock::now();

static uint64_t GetStamp()
{
	const auto delta = steady_clock::now() - start;
	const auto nsstamp = duration_cast<nanoseconds>(delta).count();
	return static_cast<uint64_t>(nsstamp);
}

static void Exit()
{
	if (events.empty())
		return;

	const char* filename = getenv("CYGPROF_FILENAME");
	if (filename == nullptr)
		filename = "cygprof.dat";

	FILE* file = fopen("cygprof.dat", "wb");
	if (file == nullptr)
	{
		fprintf(stderr, "ERROR: Failed to open file %s for writing", filename);
		return;
	}

	std::unordered_map<void*, uint32_t> addresses;
	std::vector<std::string> symbols;

	for (const CygEvent& event : events)
	{
		if (const auto found = addresses.find(event.address); addresses.end() == found)
		{
			addresses.emplace(event.address, uint32_t(symbols.size()));

			Dl_info info = {};

			if (dladdr(event.address, &info) > 0)
			{
				symbols.emplace_back(info.dli_sname);
			}
			else
			{
				char buf[64];
				snprintf(buf, sizeof buf, "%p", event.address);
				symbols.emplace_back(buf);
			}
		}
	}

	const CygHeader header = { 0xFFEEAAFF, 1, uint32_t(symbols.size()) };

	if (fwrite(&header, sizeof header, 1, file) != 1)
		fprintf(stderr, "ERROR: Failed to write header to file %s", filename);

	for (const std::string& symbol : symbols)
	{
		const uint16_t length = uint16_t(symbol.size());

		if (fwrite(&length, sizeof length, 1, file) != 1)
		{
			fprintf(stderr, "ERROR: Failed to write header to file %s", filename);
			break;
		}

		if (fwrite(&symbol[0], length, 1, file) != 1)
		{
			fprintf(stderr, "ERROR: Failed to write %hu bytes to file %s", length, filename);
			break;
		}
	}

	for (const CygEvent& event : events)
	{
		const uint32_t index = addresses[event.address];

		if (fwrite(&index, sizeof index, 1, file) != 1)
		{
			fprintf(stderr, "ERROR: Failed to write %zu bytes to file %s", sizeof index, filename);
			break;
		}

		if (fwrite(&event.stamp, sizeof event.stamp, 1, file) != 1)
		{
			fprintf(stderr, "ERROR: Failed to write %zu bytes to file %s", sizeof event.stamp, filename);
			break;
		}
	}

	if (fclose(file) != 0)
		fprintf(stderr, "ERROR: Failed to close file %s", filename);
}

static void Init()
{
	if (initialized.exchange(true))
		return; // already initialized

	atexit(Exit);

	uint64_t bytes = 0;
	const char* memory = getenv("CYGPROF_MEMORY");

	if (memory != nullptr)
	{
		char* end = nullptr;
		bytes = strtoull(memory, &end, 10);
	}

	if (bytes < 1 * 1024 * 1024)
		bytes = 64 * 1024 * 1024;

	events.reserve(bytes / sizeof(CygEvent));
}

static void FuncEnter(void* func, void* caller)
{
	Init();

	events.push_back({ func, GetStamp() });
}

static void FuncExit(void* func, void* caller)
{
	Init(); // ?

	events.push_back({ func, GetStamp() });
}

extern "C"
{
	void __cyg_profile_func_enter(void *func, void *caller)
	{
		FuncEnter(func, caller);
	}

	void __cyg_profile_func_exit (void *func, void *caller)
	{
		FuncExit(func, caller);
	}
};
