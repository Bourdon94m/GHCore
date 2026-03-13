#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  GHCore — Game Hacking / Reverse Engineering library
//
//  Include only what you need:
//
//    #include "GHCore/Memory/Memory.hpp"   → GHCore::Memory
//    #include "GHCore/Memory/Scan.hpp"     → GHCore::Scan
//    #include "GHCore/Process/Process.hpp" → GHCore::Process
//    #include "GHCore/Hooks/VmtHook.hpp"   → GHCore::Hook::VmtHook
//    #include "GHCore/Hooks/DetourHook.hpp"→ GHCore::Hook::DetourHook
//    #include "GHCore/Hooks/IatHook.hpp"   → GHCore::Hook::IatHook
//    #include "GHCore/Inject/Inject.hpp"   → GHCore::Inject
//    #include "GHCore/Utils/Utils.hpp"     → GHCore::Utils
//
//  Or include this file to pull everything at once.
// ─────────────────────────────────────────────────────────────────────────────

#include "Memory/Memory.hpp"
#include "Memory/Scan.hpp"
#include "Process/Process.hpp"
#include "Hooks/VmtHook.hpp"
#include "Hooks/DetourHook.hpp"
#include "Hooks/IatHook.hpp"
#include "Inject/Inject.hpp"
#include "Utils/Utils.hpp"
