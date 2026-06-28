#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdint>
#include "MinHook.h"

namespace Config
{
    constexpr const char* TargetModule = "GenshinImpact.exe";
    constexpr DWORD FireBeingHitEvent     = 0x8CEB5E0;
    constexpr DWORD TryDoSkill            = 0xE38CCB0;
    constexpr DWORD CheckTargetAttackable = 0x10F2EEE0;
}

namespace Globals
{
    static uintptr_t       GameBase = 0;
    static volatile LONG   Lock     = 0;
    static void* fpFireBeingHitEvent     = nullptr;
    static void* fpTryDoSkill            = nullptr;
    static void* fpCheckTargetAttackable = nullptr;
}

namespace Hooks
{
    typedef void* (__fastcall* FireBeingHitEvent_t)(__int64, unsigned int, __int64);
    typedef char  (__fastcall* CheckTargetAttackable_t)(__int64, __int64);

    static __declspec(thread) uint8_t g_HitGuard = 0;

    void* __fastcall hkFireBeingHitEvent(__int64 a1, unsigned int a2, __int64 a3)
    {
        auto original = (FireBeingHitEvent_t)Globals::fpFireBeingHitEvent;
        void* result = original(a1, a2, a3);

        if (!g_HitGuard)
        {
            g_HitGuard = 1;
            for (int i = 0; i < 14; i++)
                result = original(a1, a2, a3);
            g_HitGuard = 0;
        }
        return result;
    }

    void hkTryDoSkill()
    {
        return;
    }

    char __fastcall hkCheckTargetAttackable(__int64 a1, __int64 a2)
    {
        if (a2 && *(DWORD*)(a2 + 0x3F4) == 1)
            return 0;
        return ((CheckTargetAttackable_t)Globals::fpCheckTargetAttackable)(a1, a2);
    }
}

static DWORD WINAPI WorkerThread(LPVOID)
{
    while (!GetModuleHandleA(Config::TargetModule))
        Sleep(200);
    Sleep(3000);

    for (ULONGLONG i = 0; _InterlockedCompareExchange(&Globals::Lock, 1, 0) != 0; i++)
        Sleep(i >= 0x20 ? 1 : 0);

    HANDLE& hHeap = MH_GetHeapRef();
    if (hHeap) { _InterlockedExchange(&Globals::Lock, 0); return 0; }

    hHeap = HeapCreate(0, 0, 0);
    _InterlockedExchange(&Globals::Lock, 0);
    if (!hHeap) return 0;

    Globals::GameBase = (uintptr_t)GetModuleHandleA(Config::TargetModule);
    if (!Globals::GameBase) return 0;

    auto target1 = (void*)(Globals::GameBase + Config::FireBeingHitEvent);
    auto target2 = (void*)(Globals::GameBase + Config::TryDoSkill);
    auto target3 = (void*)(Globals::GameBase + Config::CheckTargetAttackable);

    if (MH_CreateHook(target1, (void*)Hooks::hkFireBeingHitEvent, &Globals::fpFireBeingHitEvent) == MH_OK)
        MH_EnableHook(target1);

    if (MH_CreateHook(target2, (void*)Hooks::hkTryDoSkill, &Globals::fpTryDoSkill) == MH_OK)
        MH_EnableHook(target2);

    if (MH_CreateHook(target3, (void*)Hooks::hkCheckTargetAttackable, &Globals::fpCheckTargetAttackable) == MH_OK)
        MH_EnableHook(target3);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
    }
    return TRUE;
}
