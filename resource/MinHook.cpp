#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "hde64.h"

#pragma pack(push, 1)
struct HOOK_ENTRY
{
    uintptr_t pTarget;
    uintptr_t pTrampoline;
    uintptr_t pDetour;
    uint8_t   backup[8];
    uint8_t   flags;
    uint8_t   pad[3];
    uint32_t  relayInfo;
    uint8_t   relaySrc[8];
    uint8_t   relayDst[8];
};
#pragma pack(pop)

struct RELAY_PAGE
{
    RELAY_PAGE* pNext;
    void*       pFree;
    int         nUsed;
};

struct THREAD_LIST
{
    DWORD* pIds;
    DWORD  capacity;
    DWORD  count;
};

static HANDLE         g_hHeap       = nullptr;
static HOOK_ENTRY*    g_pHooks      = nullptr;
static int            g_nCapacity   = 0;
static int            g_nCount      = 0;
static volatile LONG  g_spinLock    = 0;
static RELAY_PAGE*    g_pRelayPages = nullptr;

static void SpinLock_Acquire()
{
    for (ULONGLONG i = 0; _InterlockedCompareExchange(&g_spinLock, 1, 0) != 0; i++)
        Sleep(i >= 0x20 ? 1 : 0);
}

static void SpinLock_Release()
{
    _InterlockedExchange(&g_spinLock, 0);
}

static RELAY_PAGE* AllocateRelayPage(uintptr_t target)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    uintptr_t minAddr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    if (target > 0x40000000) {
        uintptr_t lo = target - 0x40000000;
        if (lo > minAddr) minAddr = lo;
    }
    if (maxAddr > target + 0x40000000)
        maxAddr = target + 0x40000000;
    maxAddr -= 0xFFF;

    for (RELAY_PAGE* p = g_pRelayPages; p; p = p->pNext)
        if ((uintptr_t)p >= minAddr && (uintptr_t)p < maxAddr && p->pFree)
            return p;

    RELAY_PAGE* page = nullptr;
    DWORD gran = si.dwAllocationGranularity;
    uintptr_t addr = target - (target % gran) - gran;

    while (addr >= minAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE) {
            page = (RELAY_PAGE*)VirtualAlloc((LPVOID)addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (page) goto InitPage;
        }
        if ((uintptr_t)mbi.AllocationBase < gran) break;
        addr = (uintptr_t)mbi.AllocationBase - gran;
        if (addr < minAddr) break;
    }

    addr = target + gran - (target % gran);
    while (addr <= maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE) {
            page = (RELAY_PAGE*)VirtualAlloc((LPVOID)addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (page) goto InitPage;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        addr += gran - (addr % gran);
    }

    return nullptr;

InitPage:
    {
        char* slot = (char*)page + 64;
        char* prev = nullptr;
        page->nUsed = 0;
        do {
            *(void**)slot = prev;
            prev = slot;
            page->pFree = slot;
            slot += 64;
        } while ((uintptr_t)(slot - (char*)page) <= 0xFC0);
        page->pNext = g_pRelayPages;
        g_pRelayPages = page;
    }
    return page;
}

static void FreeRelaySlot(void* pSlot)
{
    uintptr_t pageAddr = (uintptr_t)pSlot & ~0xFFFULL;
    RELAY_PAGE* prev = nullptr;
    for (RELAY_PAGE* page = g_pRelayPages; page; prev = page, page = page->pNext) {
        if ((uintptr_t)page != pageAddr) continue;
        *(uintptr_t*)pSlot = (uintptr_t)page->pFree;
        page->pFree = pSlot;
        if (--page->nUsed == 0) {
            if (prev) prev->pNext = page->pNext;
            else g_pRelayPages = page->pNext;
            VirtualFree(page, 0, MEM_RELEASE);
        }
        return;
    }
}

static bool BuildTrampoline(HOOK_ENTRY* pHook)
{
    hde64s hs;
    uint8_t* pSrc = (uint8_t*)pHook->pTarget;
    uint8_t* pRelay = (uint8_t*)pHook->pTrampoline;
    int nFixups = 0;

    // First 14 bytes of relay: absolute JMP to detour
    // FF 25 00 00 00 00 [8-byte address]
    pRelay[0] = 0xFF;
    pRelay[1] = 0x25;
    *(uint32_t*)(pRelay + 2) = 0;
    *(uintptr_t*)(pRelay + 6) = pHook->pDetour;

    // Trampoline starts at offset 14 (copies original instructions + jmp back)
    uint8_t* pDst = pRelay + 14;
    uintptr_t totalCopied = 0;

    while (totalCopied < 5)
    {
        unsigned int len = hde64_disasm(pSrc, &hs);
        if (hs.flags & F_ERROR || len == 0) return false;

        bool isRipRel = (hs.flags & F_MODRM) && hs.modrm_mod != 3 && hs.modrm_rm == 5;
        unsigned int outLen = len;

        if (hs.opcode == 0xE8 || hs.opcode == 0xE9) {
            uintptr_t abs = (uintptr_t)pSrc + len + *(int32_t*)(pSrc + 1);
            pDst[0] = hs.opcode;
            *(int32_t*)(pDst + 1) = (int32_t)(abs - (uintptr_t)pDst - 5);
            outLen = 5;
            if (nFixups < 8) {
                pHook->relaySrc[nFixups] = (uint8_t)((uintptr_t)pDst - pHook->pTrampoline);
                pHook->relayDst[nFixups] = (uint8_t)((uintptr_t)pSrc - pHook->pTarget);
                nFixups++;
            }
        }
        else if ((hs.opcode & 0xF0) == 0x70 || hs.opcode == 0xEB) {
            uintptr_t abs = (uintptr_t)pSrc + 2 + *(int8_t*)(pSrc + 1);
            if (hs.opcode == 0xEB) {
                pDst[0] = 0xE9;
                *(int32_t*)(pDst + 1) = (int32_t)(abs - (uintptr_t)pDst - 5);
                outLen = 5;
            } else {
                pDst[0] = 0x0F;
                pDst[1] = 0x80 | (hs.opcode & 0x0F);
                *(int32_t*)(pDst + 2) = (int32_t)(abs - (uintptr_t)pDst - 6);
                outLen = 6;
            }
        }
        else if (isRipRel) {
            memcpy(pDst, pSrc, len);
            int dispOff = len - 4;
            if (hs.flags & F_IMM8) dispOff -= 1;
            else if (hs.flags & F_IMM16) dispOff -= 2;
            else if (hs.flags & F_IMM32) dispOff -= 4;
            *(int32_t*)(pDst + dispOff) += (int32_t)((intptr_t)pSrc - (intptr_t)pDst);
        }
        else {
            memcpy(pDst, pSrc, len);
        }

        pSrc += hs.len;
        pDst += outLen;
        totalCopied += hs.len;
    }

    memcpy(pHook->backup, (void*)pHook->pTarget, totalCopied < 8 ? totalCopied : 7);

    if (totalCopied >= 7)
        pHook->flags |= 1;

    // JMP back to original code after copied instructions
    pDst[0] = 0xE9;
    *(int32_t*)(pDst + 1) = (int32_t)((intptr_t)pSrc - (intptr_t)pDst - 5);

    pHook->relayInfo = (pHook->relayInfo & ~0xF) | (nFixups & 0xF);
    return true;
}

static bool EnumOtherThreads(THREAD_LIST* list)
{
    list->pIds = nullptr;
    list->capacity = 0;
    list->count = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = { sizeof(te) };
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.dwSize >= 16 && te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
                if (!list->pIds) {
                    list->capacity = 128;
                    list->pIds = (DWORD*)HeapAlloc(g_hHeap, 0, 128 * sizeof(DWORD));
                    if (!list->pIds) break;
                } else if (list->count >= list->capacity) {
                    DWORD nc = list->capacity * 2;
                    auto* p = (DWORD*)HeapReAlloc(g_hHeap, 0, list->pIds, nc * sizeof(DWORD));
                    if (!p) break;
                    list->pIds = p;
                    list->capacity = nc;
                }
                list->pIds[list->count++] = te.th32ThreadID;
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return (GetLastError() == ERROR_NO_MORE_FILES);
}

static void FixupThreadContext(HANDLE hThread, int hookIdx, bool enabling)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) return;

    DWORD start = (hookIdx == -1) ? 0 : (DWORD)hookIdx;
    DWORD end   = (hookIdx == -1) ? (DWORD)g_nCount : (DWORD)(hookIdx + 1);

    for (DWORD i = start; i < end; i++) {
        HOOK_ENTRY* e = &g_pHooks[i];
        bool isEnabled = (e->flags >> 1) & 1;
        if (isEnabled == enabling) continue;

        if (enabling) {
            int cnt = e->relayInfo & 0xF;
            for (int j = 0; j < cnt; j++) {
                if (ctx.Rip == e->pTarget + e->relayDst[j]) {
                    ctx.Rip = e->pTrampoline + e->relaySrc[j];
                    SetThreadContext(hThread, &ctx);
                    break;
                }
            }
        } else {
            if ((e->flags & 1) && ctx.Rip == e->pTarget - 5) {
                ctx.Rip = e->pTarget;
                SetThreadContext(hThread, &ctx);
            } else if (ctx.Rip == e->pTrampoline) {
                ctx.Rip = e->pTarget;
                SetThreadContext(hThread, &ctx);
            }
        }
    }
}

static MH_STATUS FreezeThreads(THREAD_LIST* list, int hookIdx, bool enabling)
{
    if (!EnumOtherThreads(list)) return MH_ERROR_ALLOC;
    if (!list->pIds) return MH_OK;

    for (DWORD i = 0; i < list->count; i++) {
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, list->pIds[i]);
        if (!h) { list->pIds[i] = 0; continue; }
        if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); list->pIds[i] = 0; continue; }
        FixupThreadContext(h, hookIdx, enabling);
        CloseHandle(h);
    }
    return MH_OK;
}

static void UnfreezeThreads(THREAD_LIST* list)
{
    if (!list->pIds) return;
    for (DWORD i = 0; i < list->count; i++) {
        if (!list->pIds[i]) continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, list->pIds[i]);
        if (h) { ResumeThread(h); CloseHandle(h); }
    }
    HeapFree(g_hHeap, 0, list->pIds);
    list->pIds = nullptr;
}

static MH_STATUS PatchHook(DWORD index, bool enable)
{
    HOOK_ENTRY* e = &g_pHooks[index];
    bool hotpatch = e->flags & 1;
    uint8_t* pPatch = (uint8_t*)(hotpatch ? e->pTarget - 5 : e->pTarget);
    SIZE_T sz = hotpatch ? 7 : 5;

    DWORD oldProt;
    if (!VirtualProtect(pPatch, sz, PAGE_EXECUTE_READWRITE, &oldProt))
        return MH_ERROR_PROTECT;

    if (enable) {
        pPatch[0] = 0xE9;
        *(int32_t*)(pPatch + 1) = (int32_t)((intptr_t)e->pTrampoline - (intptr_t)pPatch - 5);
        if (hotpatch)
            *(uint16_t*)((uint8_t*)e->pTarget) = 0xF9EB;
    } else {
        if (hotpatch) {
            *(uint32_t*)pPatch = *(uint32_t*)e->backup;
            *(uint16_t*)(pPatch + 4) = *(uint16_t*)(e->backup + 4);
            pPatch[6] = e->backup[6];
        } else {
            *(uint32_t*)pPatch = *(uint32_t*)e->backup;
            pPatch[4] = e->backup[4];
        }
    }

    VirtualProtect(pPatch, sz, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), pPatch, sz);
    e->flags = (e->flags & ~6) | (enable ? 6 : 0);
    return MH_OK;
}

MH_STATUS MH_CreateHook(void* pTarget, void* pDetour, void** ppOriginal)
{
    SpinLock_Acquire();
    if (!g_hHeap) { SpinLock_Release(); return MH_ERROR_INIT; }

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pTarget, &mbi, sizeof(mbi));
    if (mbi.State != MEM_COMMIT || (mbi.Protect & 0xF0) == 0) { SpinLock_Release(); return MH_ERROR_MEMORY; }
    VirtualQuery(pDetour, &mbi, sizeof(mbi));
    if (mbi.State != MEM_COMMIT || (mbi.Protect & 0xF0) == 0) { SpinLock_Release(); return MH_ERROR_MEMORY; }

    for (int i = 0; i < g_nCount; i++)
        if ((void*)g_pHooks[i].pTarget == pTarget) { SpinLock_Release(); return MH_ERROR_DUPLICATE; }

    RELAY_PAGE* page = AllocateRelayPage((uintptr_t)pTarget);
    if (!page || !page->pFree) { SpinLock_Release(); return MH_ERROR_ALLOC; }

    void* pTramp = page->pFree;
    page->pFree = *(void**)pTramp;
    page->nUsed++;

    if (!g_pHooks) {
        g_nCapacity = 32;
        g_pHooks = (HOOK_ENTRY*)HeapAlloc(g_hHeap, 0, 32 * sizeof(HOOK_ENTRY));
        if (!g_pHooks) { FreeRelaySlot(pTramp); SpinLock_Release(); return MH_ERROR_ALLOC; }
    } else if (g_nCount >= g_nCapacity) {
        int nc = g_nCapacity * 2;
        auto* p = (HOOK_ENTRY*)HeapReAlloc(g_hHeap, 0, g_pHooks, nc * sizeof(HOOK_ENTRY));
        if (!p) { FreeRelaySlot(pTramp); SpinLock_Release(); return MH_ERROR_ALLOC; }
        g_pHooks = p;
        g_nCapacity = nc;
    }

    HOOK_ENTRY* entry = &g_pHooks[g_nCount];
    memset(entry, 0, sizeof(HOOK_ENTRY));
    entry->pTarget = (uintptr_t)pTarget;
    entry->pTrampoline = (uintptr_t)pTramp;
    entry->pDetour = (uintptr_t)pDetour;

    if (!BuildTrampoline(entry)) { FreeRelaySlot(pTramp); SpinLock_Release(); return MH_ERROR_RELAY; }

    g_nCount++;
    if (ppOriginal) *ppOriginal = (void*)((uint8_t*)pTramp + 14);
    SpinLock_Release();
    return MH_OK;
}

MH_STATUS MH_EnableHook(void* pTarget)
{
    SpinLock_Acquire();
    if (!g_hHeap) { SpinLock_Release(); return MH_ERROR_INIT; }

    int idx = -1;
    for (int i = 0; i < g_nCount; i++)
        if ((void*)g_pHooks[i].pTarget == pTarget) { idx = i; break; }
    if (idx == -1) { SpinLock_Release(); return MH_ERROR_NOT_FOUND; }
    if ((g_pHooks[idx].flags >> 1) & 1) { SpinLock_Release(); return MH_ERROR_NOOP_EN; }

    THREAD_LIST tl = {};
    MH_STATUS st = FreezeThreads(&tl, idx, true);
    if (st == MH_OK) st = PatchHook((DWORD)idx, true);
    UnfreezeThreads(&tl);
    SpinLock_Release();
    return st;
}

MH_STATUS MH_DisableHook(void* pTarget)
{
    SpinLock_Acquire();
    if (!g_hHeap) { SpinLock_Release(); return MH_ERROR_INIT; }

    int idx = -1;
    for (int i = 0; i < g_nCount; i++)
        if ((void*)g_pHooks[i].pTarget == pTarget) { idx = i; break; }
    if (idx == -1) { SpinLock_Release(); return MH_ERROR_NOT_FOUND; }
    if (!((g_pHooks[idx].flags >> 1) & 1)) { SpinLock_Release(); return MH_ERROR_NOOP_DIS; }

    THREAD_LIST tl = {};
    MH_STATUS st = FreezeThreads(&tl, idx, false);
    if (st == MH_OK) st = PatchHook((DWORD)idx, false);
    UnfreezeThreads(&tl);
    SpinLock_Release();
    return st;
}

MH_STATUS MH_EnableAllHooks()
{
    SpinLock_Acquire();
    if (!g_hHeap) { SpinLock_Release(); return MH_ERROR_INIT; }
    THREAD_LIST tl = {};
    FreezeThreads(&tl, -1, true);
    for (int i = 0; i < g_nCount; i++)
        if (!((g_pHooks[i].flags >> 1) & 1)) PatchHook((DWORD)i, true);
    UnfreezeThreads(&tl);
    SpinLock_Release();
    return MH_OK;
}

MH_STATUS MH_DisableAllHooks()
{
    SpinLock_Acquire();
    if (!g_hHeap) { SpinLock_Release(); return MH_ERROR_INIT; }
    THREAD_LIST tl = {};
    FreezeThreads(&tl, -1, false);
    for (int i = 0; i < g_nCount; i++)
        if ((g_pHooks[i].flags >> 1) & 1) PatchHook((DWORD)i, false);
    UnfreezeThreads(&tl);
    SpinLock_Release();
    return MH_OK;
}

void MH_Uninitialize()
{
    MH_DisableAllHooks();
    SpinLock_Acquire();
    if (g_hHeap) {
        RELAY_PAGE* page = g_pRelayPages;
        g_pRelayPages = nullptr;
        while (page) { RELAY_PAGE* n = page->pNext; VirtualFree(page, 0, MEM_RELEASE); page = n; }
        if (g_pHooks) { HeapFree(g_hHeap, 0, g_pHooks); g_pHooks = nullptr; }
        HeapDestroy(g_hHeap);
        g_hHeap = nullptr;
        g_nCapacity = 0;
        g_nCount = 0;
    }
    SpinLock_Release();
}

HANDLE& MH_GetHeapRef() { return g_hHeap; }
