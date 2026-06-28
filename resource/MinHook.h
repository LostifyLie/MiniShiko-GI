#pragma once
#include <cstdint>

enum MH_STATUS : unsigned int
{
    MH_OK              = 0,
    MH_ERROR_INIT      = 2,
    MH_ERROR_DUPLICATE = 3,
    MH_ERROR_NOT_FOUND = 4,
    MH_ERROR_NOOP_EN   = 5,
    MH_ERROR_NOOP_DIS  = 6,
    MH_ERROR_MEMORY    = 7,
    MH_ERROR_RELAY     = 8,
    MH_ERROR_ALLOC     = 9,
    MH_ERROR_PROTECT   = 10,
};

MH_STATUS MH_CreateHook(void* pTarget, void* pDetour, void** ppOriginal);
MH_STATUS MH_EnableHook(void* pTarget);
MH_STATUS MH_DisableHook(void* pTarget);
MH_STATUS MH_EnableAllHooks();
MH_STATUS MH_DisableAllHooks();
void      MH_Uninitialize();
HANDLE&   MH_GetHeapRef();
