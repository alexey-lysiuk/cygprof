
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <chrono>
#include <vector>

struct CygHeader
{
	uint32_t magic;
	uint32_t version;
	uint64_t base;
};

struct CygEvent
{
	uint64_t address;
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

	const CygHeader header = { 0xFFEEAAFF, 1, 0x0 }; // TODO: base address

	if (fwrite(&header, sizeof header, 1, file) != 1)
		fprintf(stderr, "ERROR: Failed to write header to file %s", filename);

	const size_t bytes = events.size() * sizeof(CygEvent);

	if (fwrite(&events[0], bytes, 1, file) != 1)
		fprintf(stderr, "ERROR: Failed to write %zu bytes to file %s", bytes, filename);

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

	events.push_back({ reinterpret_cast<uint64_t>(func), GetStamp() });
}

static void FuncExit(void* func, void* caller)
{
	Init(); // ?

	events.push_back({ reinterpret_cast<uint64_t>(func), GetStamp() });
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
