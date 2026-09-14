#pragma once

//
//=============================================================================
// SCFW
//=============================================================================
//
// A compile-time shellcode framework for building position-independent
// executables.
//
// This module provides compile-time declaration of APIs that are resolved
// at runtime. It uses recursive template inheritance to build a dispatch table
// with zero metadata overhead.
//
//=============================================================================
// USAGE
//=============================================================================
//
//   #include <scfw/runtime.h>
//   #include <scfw/platform/windows/usermode.h>
//
//   IMPORT_BEGIN();
//       IMPORT_MODULE("kernel32.dll");
//           IMPORT_SYMBOL(Sleep);
//       IMPORT_MODULE("user32.dll", FLAGS(SCFW_FLAG_DYNAMIC_LOAD));
//           IMPORT_SYMBOL(MessageBoxA);
//   IMPORT_END();
//
//   namespace sc {
//       void __fastcall entry(void* argument1, void* argument2) {
//           Sleep(1000);
//           MessageBoxA(NULL, _T("Hi"), _T("scfw"), MB_OK);
//       }
//   } // namespace sc
//
//=============================================================================
// COMPILE-TIME OPTIONS
//=============================================================================
//
// These are #define'd before including runtime.h or set via CMake.
// Each one adds code/data to the output, so only enable what you need.
//
//   SCFW_ENABLE_CLEANUP       - Self-cleanup: the shellcode frees its own
//                               memory on exit via VirtualFree. MUST be set
//                               via CMake (not just #define) because the
//                               assembly startup code depends on it too.
//
//   SCFW_ENABLE_LOAD_MODULE   - Resolves LoadLibraryA at init time. Required
//                               by SCFW_FLAG_DYNAMIC_LOAD to load DLLs not
//                               already present in the target process.
//
//   SCFW_ENABLE_UNLOAD_MODULE - Resolves FreeLibrary at init time. Required
//                               by SCFW_FLAG_DYNAMIC_UNLOAD.
//
//   SCFW_ENABLE_LOOKUP_SYMBOL - Resolves GetProcAddress at init time.
//                               Required by SCFW_FLAG_DYNAMIC_RESOLVE.
//
//   SCFW_ENABLE_XOR_STRING    - XOR-encodes all strings passed through _T()
//                               at compile time and decodes them in-place at
//                               runtime on first access. Prevents module and
//                               symbol name strings from appearing in
//                               plaintext in the binary.
//
// PER-ENTRY FLAGS (passed via FLAGS() in IMPORT_MODULE / IMPORT_SYMBOL):
//
//   SCFW_FLAG_DYNAMIC_RESOLVE - Use GetProcAddress for symbol lookup instead
//     (0x01)                    of manually parsing the PE export table.
//                               Implies STRING_SYMBOL (names must be strings).
//                               Set on a module to affect all its symbols.
//                               Requires SCFW_ENABLE_LOOKUP_SYMBOL.
//
//   SCFW_FLAG_DYNAMIC_LOAD    - Use LoadLibraryA to load the module, instead
//     (0x02)                    of finding it in the PEB. For DLLs not already
//                               loaded in the target process (e.g. user32.dll).
//                               Requires SCFW_ENABLE_LOAD_MODULE.
//
//   SCFW_FLAG_DYNAMIC_UNLOAD  - FreeLibrary the module during destroy().
//     (0x04)                    Only valid together with DYNAMIC_LOAD.
//                               Requires SCFW_ENABLE_UNLOAD_MODULE.
//
//   SCFW_FLAG_STRING_MODULE   - Find the module by string name comparison
//     (0x08)                    instead of FNV-1a hash. Larger output
//                               (full module name string in binary).
//
//   SCFW_FLAG_STRING_SYMBOL   - Find the symbol by string name comparison
//     (0x10)                    instead of FNV-1a hash. Larger output
//                               (full symbol name string in binary).
//
// DEFAULT FLAGS (define before including runtime.h):
//
//   SCFW_MODULE_DEFAULT_FLAGS - Default flags for IMPORT_MODULE (default: 0).
//   SCFW_ENTRY_DEFAULT_FLAGS  - Default flags for IMPORT_SYMBOL (default: 0).
//
//=============================================================================
// HOW IT WORKS
//=============================================================================
//
// The dispatch table is built at compile time using C++ template
// metaprogramming. Each IMPORT_MODULE / IMPORT_SYMBOL macro creates a
// new struct (dispatch_table_impl<N+1>) that inherits from the previous
// one (<N>), forming a chain. __COUNTER__ gives each macro a unique ID.
//
//   dispatch_table_impl<0, Mode>    base class
//     - holds optional fn ptrs: cleanup_, free_, load_module_, etc.
//     - provides find_module(), load_module(), lookup_symbol()
//           |
//   dispatch_table_impl<1, Mode>    IMPORT_MODULE("kernel32.dll")
//     - adds: void* module_
//     - init() calls find_module() or load_module()
//     - destroy() optionally calls unload_module()
//           |
//   dispatch_table_impl<2, Mode>    IMPORT_SYMBOL(Sleep)
//     - adds: slot_Sleep_ (function pointer)
//     - init() calls lookup_symbol() on parent's module_
//           |
//   dispatch_table                  final alias (defined by IMPORT_END)
//
// init() chains upward: base first, then each entry in order.
// destroy() chains downward: last entry first, back to base.
//
// After IMPORT_END, user code accesses symbols through proxy objects
// in the sc:: namespace (e.g., sc::Sleep). These proxies read the
// function pointer from __dispatch_table at runtime.
//
//=============================================================================
// SECTION ORDERING
//=============================================================================
//
// Everything is merged into a single .text section (via linker /MERGE).
// The linker orders .text$* subsections alphabetically:
//
//   Section       Contents                  Source
//   ------------- ------------------------- -------------------------
//   .text$00      _init                     lib/src/arch/*/init.S
//   .text$10      _start, _pc, _cleanup_*   lib/src/arch/*/start.S
//   .text$20      _entry                    IMPORT_END() macro
//   .text$aaa     framework code            runtime.h, crt0.h, etc.
//   .text$yyy     user code                 after IMPORT_END()
//   .data$00      __dispatch_table          IMPORT_END() macro
//   .data$yyy     user data                 after IMPORT_END()
//
// _init must be first (it's the PE entry point). User code comes last.
// /MERGE appends whole output sections, so .data$* lands after every .text$*.
//
//=============================================================================
// MEMORY LAYOUT
//=============================================================================
//
// The assembly startup code (lib/src/x64/start.S, lib/src/x86/start.S)
// directly accesses `cleanup_` and `free_` at hardcoded offsets:
//
//   x86 Layout:                      x64 Layout:
//   +-------------------------+      +-------------------------+
//   | +0:  cleanup_           |      | +0:  cleanup_           |
//   | +4:  free_              |      | +8:  free_              |
//   | +8:  load_module_       |      | +16: load_module_       |
//   | +12: unload_module_     |      | +24: unload_module_     |
//   | +16: lookup_symbol_     |      | +32: lookup_symbol_     |
//   +-------------------------+      +-------------------------+
//
// IMPORTANT: DO NOT reorder these members without updating assembly!
//

//
// Place all framework code in `.text$aaa` (after `_entry` in `.text$20`,
// before user code in `.text$yyy`).
//
#pragma code_seg(".text$aaa")

#include "crt0.h"
#include "runtime/fnv1a.h"
#include "runtime/pic.h"
#include "runtime/xorstr.h"

//=============================================================================
// Flags & declarations.
//=============================================================================

//
// Use `GetProcAddress` for symbol lookup instead of manual PE export parsing.
// Implies `STRING_SYMBOL` (names must be passed as strings, not hashes).
// Set on a module to affect all its symbols. Requires `SCFW_ENABLE_LOOKUP_SYMBOL`.
//
#define SCFW_FLAG_DYNAMIC_RESOLVE 0x01

//
// Use `LoadLibraryA` to load the module instead of searching the PEB.
// For DLLs not already loaded in the target process (e.g. `user32.dll`).
// Requires `SCFW_ENABLE_LOAD_MODULE`.
//
#define SCFW_FLAG_DYNAMIC_LOAD    0x02

//
// `FreeLibrary` the module during `destroy()`. Only valid with `DYNAMIC_LOAD`.
// Requires `SCFW_ENABLE_UNLOAD_MODULE`.
//
#define SCFW_FLAG_DYNAMIC_UNLOAD  0x04

//
// Find the module by string comparison instead of FNV-1a hash.
// Larger output (full module name string ends up in the binary).
//
#define SCFW_FLAG_STRING_MODULE   0x08

//
// Find the symbol by string comparison instead of FNV-1a hash.
// Larger output (full symbol name string ends up in the binary).
//
#define SCFW_FLAG_STRING_SYMBOL   0x10

//
// Default flags for `IMPORT_MODULE` / `IMPORT_SYMBOL` when `FLAGS()` is not specified.
// Override these before including `runtime.h` if you want all entries to share
// the same flags (e.g., `#define SCFW_MODULE_DEFAULT_FLAGS SCFW_FLAG_STRING_MODULE`).
//
#ifndef SCFW_MODULE_DEFAULT_FLAGS
#   define SCFW_MODULE_DEFAULT_FLAGS 0
#endif

#ifndef SCFW_ENTRY_DEFAULT_FLAGS
#   define SCFW_ENTRY_DEFAULT_FLAGS 0
#endif

//
// User-defined entry point. Called by the framework after the dispatch table
// is initialized. Must be implemented by the user.
//
extern "C" void __fastcall entry(void* argument1, void* argument2);

//
// FLAGS() macro for passing per-entry flags to `IMPORT_MODULE` / `IMPORT_SYMBOL`.
// Expands to two tokens (`SCFW_F_, value`), which the variadic argument counting
// trick uses to detect the presence of flags and route to the right overload.
//
// Example: IMPORT_MODULE("user32.dll", FLAGS(SCFW_FLAG_DYNAMIC_LOAD))
//   expands to: IMPORT_MODULE("user32.dll", SCFW_F_, SCFW_FLAG_DYNAMIC_LOAD)
//   which is 3 args -> dispatched to SCFW_IM_3.
//
#define FLAGS(x) SCFW_F_, x

//
// IMPORT_BEGIN() - forward-declares the dispatch_table type and the
// `__dispatch_table` global. Must come before any `IMPORT_MODULE` / `IMPORT_SYMBOL`.
//

#define IMPORT_BEGIN()                                                        \
    namespace sc {                                                            \
    namespace detail {                                                        \
    __declspec(allocate(".data$00"))                                          \
    extern "C" dispatch_table __dispatch_table;                               \
    } /* namespace detail */                                                  \
    } /* namespace sc */

//
// IMPORT_END() - seals the dispatch table and generates the _entry function.
//
// - Defines dispatch_table as the final dispatch_table_impl specialization.
// - Instantiates `__dispatch_table` in `.data$00` (merged into `.text`).
//   The explicit section is needed. A zero-initialized global goes to `.bss`,
//   which has no file bytes, so the table would sit past SizeOfRawData and be
//   missing from the extracted `.bin`.
// - Creates `_entry()` in `.text$20` which:
//     - gets the PIC-adjusted address of `__dispatch_table`,
//     - calls `dt->init()` to resolve all modules and symbols,
//     - calls the user's `entry()` function,
//     - calls `dt->destroy()` for cleanup (e.g., `FreeLibrary`).
// - Switches to `.text$yyy` and `.data$yyy` so all subsequent user code and
//   initialized user data go there.
//

#define IMPORT_END()                                                          \
    namespace sc {                                                            \
    namespace detail {                                                        \
    struct dispatch_table                                                     \
        : dispatch_table_impl<__COUNTER__, SCFW_MODE> {};                     \
    __pragma(data_seg(".data$00"))                                            \
    __declspec(allocate(".data$00"))                                          \
    extern "C" dispatch_table __dispatch_table{};                             \
                                                                              \
    __pragma(code_seg(".text$20"))                                            \
    __declspec(allocate(".text$20"))                                          \
    extern "C" void __fastcall _entry(void* argument1, void* argument2) {     \
        auto dt = reinterpret_cast<dispatch_table*>(_(&__dispatch_table));    \
                                                                              \
        auto err = dt->init(argument1, argument2);                            \
        if (err) return;                                                      \
                                                                              \
        entry(argument1, argument2);                                          \
                                                                              \
        dt->destroy(argument1, argument2);                                    \
    }                                                                         \
    } /* namespace detail */                                                  \
    } /* namespace sc */                                                      \
                                                                              \
    __pragma(code_seg(".text$yyy"))                                           \
    __pragma(data_seg(".data$yyy"))

//
// IMPORT_MODULE(name [, FLAGS(flags)]) - declare a DLL dependency.
//
// Creates a `dispatch_table_impl` entry that resolves the module during init.
// Subsequent `IMPORT_SYMBOL` calls will look up exports from this module.
//
// Argument expansion (`FLAGS()` expands to 2 tokens: `SCFW_F_, value`):
//   1 arg:  "name"                       -> uses SCFW_MODULE_DEFAULT_FLAGS
//   3 args: "name", SCFW_F_, flags       -> uses specified flags
//   (2 args is not possible since FLAGS() always expands to 2 tokens)
//
#define IMPORT_MODULE(...)                                                    \
    SCFW_IM_EXPAND(SCFW_IM_NARGS(__VA_ARGS__, _3, _2, _1)(__COUNTER__, __VA_ARGS__))

#define SCFW_IM_EXPAND(...) __VA_ARGS__
#define SCFW_IM_NARGS(_1, _2, _3, N, ...) SCFW_IM##N

// 1 arg: IMPORT_MODULE("kernel32.dll") -> default flags.
#define SCFW_IM_1(Id, Module)                                                 \
    SCFW_IMPORT_MODULE_IMPL(Id, Module, SCFW_MODULE_DEFAULT_FLAGS)

// 3 args: IMPORT_MODULE("user32.dll", FLAGS(SCFW_FLAG_DYNAMIC_LOAD)) -> custom flags.
#define SCFW_IM_3(Id, Module, Marker, Flags)                                  \
    SCFW_IMPORT_MODULE_IMPL(Id, Module, Flags)

#define SCFW_IMPORT_MODULE_IMPL(Id, Module, Flags)                            \
    namespace sc {                                                            \
    namespace detail {                                                        \
    template<>                                                                \
    struct dispatch_table_impl<Id + 1, SCFW_MODE>                             \
        : dispatch_table_impl<Id, SCFW_MODE>                                  \
    {                                                                         \
        static_assert(!(((Flags) & SCFW_FLAG_DYNAMIC_UNLOAD) &&               \
                       !((Flags) & SCFW_FLAG_DYNAMIC_LOAD)),                  \
            Module ": DYNAMIC_UNLOAD requires DYNAMIC_LOAD");                 \
                                                                              \
        static constexpr entry_kind entry_type = entry_kind::module;          \
        static constexpr uint32_t module_flags = Flags;                       \
                                                                              \
        __forceinline                                                         \
        int init(void* argument1, void* argument2) {                          \
            auto err = dispatch_table_impl<Id, SCFW_MODE>::init(argument1,    \
                                                                argument2);   \
            if (err) return err;                                              \
            if constexpr (module_flags & SCFW_FLAG_DYNAMIC_LOAD) {            \
                module_ = load_module(_T(Module));                            \
            } else if constexpr (module_flags & SCFW_FLAG_STRING_MODULE) {    \
                module_ = find_module(_T(Module));                            \
            } else {                                                          \
                module_ = find_module(fnv1a_hash(Module));                    \
            }                                                                 \
            if (!module_) return Id + 1;                                      \
            return 0;                                                         \
        }                                                                     \
                                                                              \
        __forceinline                                                         \
        void destroy(void* argument1, void* argument2) {                      \
            if constexpr ((module_flags & SCFW_FLAG_DYNAMIC_LOAD) &&          \
                          (module_flags & SCFW_FLAG_DYNAMIC_UNLOAD)) {        \
                if (module_) {                                                \
                    unload_module(current_module());                          \
                }                                                             \
            }                                                                 \
            dispatch_table_impl<Id, SCFW_MODE>::destroy(argument1,            \
                                                        argument2);           \
        }                                                                     \
                                                                              \
    protected:                                                                \
        __forceinline                                                         \
        void* current_module() const {                                        \
            return module_;                                                   \
        }                                                                     \
                                                                              \
    private:                                                                  \
        void* module_{};                                                      \
    };                                                                        \
    } /* namespace detail */                                                  \
    } /* namespace sc */

//
// IMPORT_SYMBOL(name [, type] [, FLAGS(flags)]) - declare an API import.
//
// Two modes:
//   Callable: IMPORT_SYMBOL(Sleep) - type is inferred as `decltype(&::Sleep)`.
//             Creates `sc::Sleep(...)` that forwards to the resolved pointer.
//
//   Value:    IMPORT_SYMBOL(SomeExport, int*) - explicit type, not callable.
//             Creates `sc::SomeExport` as a `proxy_value<int*>`.
//
// Argument expansion (`FLAGS()` expands to 2 tokens: `SCFW_F_, value`):
//   1 arg:  Name                         -> callable, default flags
//   2 args: Name, Type                   -> value, default flags
//   3 args: Name, SCFW_F_, val           -> callable, custom flags
//   4 args: Name, Type, SCFW_F_, val     -> value, custom flags
//
#define IMPORT_SYMBOL(...)                                                    \
    SCFW_IS_EXPAND(SCFW_IS_NARGS(__VA_ARGS__, _4, _3, _2, _1)(__COUNTER__, __VA_ARGS__))

#define SCFW_IS_EXPAND(...) __VA_ARGS__
#define SCFW_IS_NARGS(_1, _2, _3, _4, N, ...) SCFW_IS##N

// 1 arg: IMPORT_SYMBOL(Sleep) -> callable with default flags.
#define SCFW_IS_1(Id, Name)                                                   \
    SCFW_IMPORT_SYMBOL_CALLABLE_IMPL(Id, Name, SCFW_ENTRY_DEFAULT_FLAGS)

// 2 args: IMPORT_SYMBOL(Name, Type) -> value import with default flags.
// Can't be FLAGS() here because FLAGS() always expands to 2 tokens,
// making the total 3 args (routed to SCFW_IS_3 instead).
#define SCFW_IS_2(Id, Name, Type)                                             \
    SCFW_IMPORT_SYMBOL_VALUE_IMPL(Id, Name, Type, SCFW_ENTRY_DEFAULT_FLAGS)

// 3 args: IMPORT_SYMBOL(Sleep, FLAGS(x)) -> callable with custom flags.
#define SCFW_IS_3(Id, Name, Marker, Flags)                                    \
    SCFW_IMPORT_SYMBOL_CALLABLE_IMPL(Id, Name, Flags)

// 4 args: IMPORT_SYMBOL(Name, Type, FLAGS(x)) -> value with custom flags.
#define SCFW_IS_4(Id, Name, Type, Marker, Flags)                              \
    SCFW_IMPORT_SYMBOL_VALUE_IMPL(Id, Name, Type, Flags)

//
// Callable import: infers the type from the Windows SDK declaration,
// creates the dispatch table entry + a callable proxy in `sc::Name`.
//

#define SCFW_IMPORT_SYMBOL_CALLABLE_IMPL(Id, Name, Flags)                     \
    SCFW_IMPORT_SYMBOL(Id, Name, decltype(&::Name), Flags);                   \
    SCFW_CALLABLE_IMPL(Id, Name)

//
// Value import: uses an explicit type, creates the dispatch table entry
// + a value proxy in `sc::Name` (read/write via operator overloads).
//

#define SCFW_IMPORT_SYMBOL_VALUE_IMPL(Id, Name, Type, Flags)                  \
    SCFW_IMPORT_SYMBOL(Id, Name, Type, Flags);                                \
    SCFW_VALUE_IMPL(Id, Name, Type)

//
// Core dispatch table entry for a symbol. Creates a new template
// specialization that inherits from the previous entry and adds
// a `slot_Name_` field. The `init()` method resolves the symbol using
// one of three strategies (in priority order):
//
//   - (default)       -> manual PE parsing with FNV-1a hash comparison.
//   - STRING_SYMBOL   -> manual PE parsing with strcmp.
//   - DYNAMIC_RESOLVE -> `GetProcAddress` (via base class `lookup_symbol_`).
//
// Flags can come from the symbol itself (`entry_flags`) or be inherited
// from the parent module (looked up via `lookup_flags_v`).
//

#define SCFW_IMPORT_SYMBOL(Id, Name, Type, Flags)                             \
    namespace sc {                                                            \
    namespace detail {                                                        \
    template<>                                                                \
    struct dispatch_table_impl<Id + 1, SCFW_MODE>                             \
        : dispatch_table_impl<Id, SCFW_MODE>                                  \
    {                                                                         \
        static_assert(!((Flags) & SCFW_FLAG_DYNAMIC_LOAD),                    \
            #Name ": DYNAMIC_LOAD can only be used with IMPORT_MODULE");      \
        static_assert(!((Flags) & SCFW_FLAG_DYNAMIC_UNLOAD),                  \
            #Name ": DYNAMIC_UNLOAD can only be used with IMPORT_MODULE");    \
        static_assert(!((Flags) & SCFW_FLAG_STRING_MODULE),                   \
            #Name ": STRING_MODULE can only be used with IMPORT_MODULE");     \
                                                                              \
        friend struct callable_##Name;                                        \
        friend struct value_##Name;                                           \
                                                                              \
        static constexpr entry_kind entry_type = entry_kind::symbol;          \
        static constexpr uint32_t entry_flags = Flags;                        \
                                                                              \
        __forceinline                                                         \
        int init(void* argument1, void* argument2) {                          \
            auto err = dispatch_table_impl<Id, SCFW_MODE>::init(argument1,    \
                                                                argument2);   \
            if (err) return err;                                              \
                                                                              \
            constexpr bool dynamic_resolve =                                  \
                (entry_flags & SCFW_FLAG_DYNAMIC_RESOLVE) ||                  \
                (lookup_flags_v<Id, SCFW_MODE, entry_kind::module> &          \
                    SCFW_FLAG_DYNAMIC_RESOLVE);                               \
                                                                              \
            if constexpr (dynamic_resolve) {                                  \
                /* string_symbol is implied */                                \
                slot_##Name##_ =                                              \
                    lookup_symbol<Type>(current_module(), _T(#Name));         \
            } else {                                                          \
                constexpr bool string_symbol =                                \
                    (entry_flags & SCFW_FLAG_STRING_SYMBOL) ||                \
                    (lookup_flags_v<Id, SCFW_MODE, entry_kind::module> &      \
                        SCFW_FLAG_STRING_SYMBOL);                             \
                                                                              \
                if constexpr (string_symbol) {                                \
                    slot_##Name##_ =                                          \
                        mode::lookup_symbol<Type>(current_module(),           \
                                                  _T(#Name));                 \
                } else {                                                      \
                    slot_##Name##_ =                                          \
                        mode::lookup_symbol<Type>(current_module(),           \
                                                  fnv1a_hash(#Name));         \
                }                                                             \
            }                                                                 \
                                                                              \
            return slot_##Name##_ ? 0 : Id + 1;                               \
        }                                                                     \
                                                                              \
        __forceinline                                                         \
        void destroy(void* argument1, void* argument2) {                      \
            dispatch_table_impl<Id, SCFW_MODE>::destroy(argument1,            \
                                                        argument2);           \
        }                                                                     \
                                                                              \
    private:                                                                  \
        Type slot_##Name##_{};                                                \
    };                                                                        \
    } /* namespace detail */                                                  \
    } /* namespace sc */

//
// Callable proxy. Creates `sc::Name` as a zero-size global whose `operator()`
// reads the function pointer from `__dispatch_table` and calls through it.
//
// For `IMPORT_SYMBOL(Sleep)`, this generates:
//
//   struct callable_Sleep : proxy_callable<decltype(&::Sleep), callable_Sleep> {
//       decltype(&::Sleep) get() const {
//           return ((dispatch_table_impl<N>*) _(&__dispatch_table))->slot_Sleep_;
//       }
//   };
//   inline callable_Sleep Sleep{};   // in namespace sc
//

#define SCFW_CALLABLE_IMPL(Id, Name)                                          \
    namespace sc {                                                            \
    namespace detail {                                                        \
    struct callable_##Name                                                    \
        : proxy_callable<decltype(&::Name), callable_##Name>                  \
    {                                                                         \
        friend struct proxy_callable<decltype(&::Name), callable_##Name>;     \
                                                                              \
    private:                                                                  \
        __forceinline                                                         \
        decltype(&::Name) get() const {                                       \
            return reinterpret_cast<dispatch_table_impl<Id + 1, SCFW_MODE>*>(\
                _(&__dispatch_table))->slot_##Name##_;                        \
        }                                                                     \
    };                                                                        \
    } /* namespace detail */                                                  \
    inline detail::callable_##Name Name{};                                    \
    } /* namespace sc */

//
// Value proxy. Creates `sc::Name` as a zero-size global that provides
// read/write access to the slot via operator overloads (`operator T&`,
// `operator=`, `operator&`, `operator bool`).
//
// Used for non-callable exports (data pointers, etc.).
//

#define SCFW_VALUE_IMPL(Id, Name, Type)                                       \
    namespace sc {                                                            \
    namespace detail {                                                        \
    struct value_##Name                                                       \
        : proxy_value<Type, value_##Name>                                     \
    {                                                                         \
        friend struct proxy_value<Type, value_##Name>;                        \
                                                                              \
        using proxy_value<Type, value_##Name>::operator=;                     \
                                                                              \
    private:                                                                  \
        __forceinline                                                         \
        Type* get() const {                                                   \
            return &reinterpret_cast<dispatch_table_impl<Id + 1, SCFW_MODE>*>(\
                _(&__dispatch_table))->slot_##Name##_;                        \
        }                                                                     \
    };                                                                        \
    } /* namespace detail */                                                  \
    inline detail::value_##Name Name{};                                       \
    } /* namespace sc */

//
// GLOBAL(Type, Name [, init]) - declare a global variable in `sc::`.
//
// On x86, global variable addresses require relocation. GLOBAL creates
// a proxy that computes the runtime address using `_pic()`.
//
// Example:
//   GLOBAL(int, counter, 0);       // Declares sc::counter.
//   sc::counter = 42;              // Assignment through proxy.
//   int* ptr = &sc::counter;       // Gets runtime address.
//
// On x64, this is a simple static variable (RIP-relative addressing works).
//

#define GLOBAL(Type, Name, ...)                                               \
    SCFW_GLOBAL_IMPL(Type, Name, SCFW_GLOBAL_DEFAULT_INIT(__VA_ARGS__))

#define SCFW_GLOBAL_DEFAULT_INIT(...)                                         \
    SCFW_GLOBAL_DEFAULT_INIT_I(__VA_ARGS__ __VA_OPT__(,) {}, )
#define SCFW_GLOBAL_DEFAULT_INIT_I(expr, ...) = expr

#if _M_IX86
//
// x86: wraps the global in a proxy_value that uses `_pic()` to compute the
// runtime address. The actual storage is `sc::detail::Name_`, and
// `sc::Name` is a zero-size proxy that redirects all access through `_pic()`.
//
#define SCFW_GLOBAL_IMPL(Type, Name, Initializer)                             \
    namespace sc {                                                            \
    namespace detail {                                                        \
    static Type Name##_ Initializer;                                          \
                                                                              \
    struct global_##Name                                                      \
        : proxy_value<Type, global_##Name>                                    \
    {                                                                         \
        friend struct proxy_value<Type, global_##Name>;                       \
                                                                              \
        using proxy_value<Type, global_##Name>::operator=;                    \
                                                                              \
    private:                                                                  \
        __forceinline                                                         \
        Type* get() const {                                                   \
            return _(&Name##_);                                               \
        }                                                                     \
    };                                                                        \
    } /* namespace detail */                                                  \
    inline detail::global_##Name Name{};                                      \
    } /* namespace sc */
#else
//
// x64: RIP-relative addressing handles relocation, so no proxy needed.
// Just a plain static variable in `namespace sc`.
//
#define SCFW_GLOBAL_IMPL(Type, Name, Initializer)                             \
    namespace sc {                                                            \
    static Type Name Initializer;                                             \
    } /* namespace sc */
#endif

namespace sc {
namespace detail {

//
// Tags for dispatch table entries. Used by `lookup_flags` to walk the
// inheritance chain and find the nearest module or symbol entry.
//

enum class entry_kind {
    module,
    symbol
};

//
// Primary template for platform-specific type bindings. Specialized by
// `usermode.h` / `kernelmode.h` to map abstract operations (`load_module`,
// `lookup_symbol`, etc.) to concrete function pointer types and
// implementations.
//

template <typename Mode>
struct mode_traits {
#ifdef SCFW_ENABLE_CLEANUP
    using cleanup_fn = void;
    using free_fn = void;
#endif
#ifdef SCFW_ENABLE_LOAD_MODULE
    using load_module_fn = void;
#endif
#ifdef SCFW_ENABLE_UNLOAD_MODULE
    using unload_module_fn = void;
#endif
#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
    using lookup_symbol_fn = void;
#endif

    //
    // Manual PE export table lookup. Overloaded for string name and
    // FNV-1a hash. Implemented in `common.h` (parses PE headers directly).
    //

    template <typename F>
    static F lookup_symbol(void* module, const char* name);

    template <typename F>
    static F lookup_symbol(void* module, uint32_t hash);
};

//
// Base-level function pointer storage for the dispatch table.
//

template <typename Mode>
struct dispatch_table_fields {
    using mode = mode_traits<Mode>;

    //
    // Optional function pointers, conditionally compiled.
    // The assembly startup code reads `cleanup_` and `free_` at hardcoded
    // offsets (see `MEMORY LAYOUT` diagram above).
    //

#ifdef SCFW_ENABLE_CLEANUP
    typename mode::cleanup_fn cleanup_;
    typename mode::free_fn free_;
#endif
#ifdef SCFW_ENABLE_LOAD_MODULE
    typename mode::load_module_fn load_module_;
#endif
#ifdef SCFW_ENABLE_UNLOAD_MODULE
    typename mode::unload_module_fn unload_module_;
#endif
#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
    typename mode::lookup_symbol_fn lookup_symbol_;
#endif
};

//
// Combines function pointer storage with optional platform-specific state.
// Uses empty base optimization: when `mode_traits<Mode>` is stateless
// (e.g., usermode), the `mode_` member is omitted to avoid wasting space
// in the dispatch table.
//

template <typename Mode, bool = std::is_empty_v<mode_traits<Mode>>>
struct dispatch_table_storage
    : dispatch_table_fields<Mode>
{
    mode_traits<Mode> mode_;
};

//
// Specialization for stateless `mode_traits<Mode>` (e.g., usermode).
// Inherits function pointer fields without adding a `mode_` member.
//

template <typename Mode>
struct dispatch_table_storage<Mode, true>
    : dispatch_table_fields<Mode>
{};

//
// Forward declaration. The actual type is defined by `IMPORT_END()` as
// the final link in the `dispatch_table_impl` inheritance chain.
//

struct dispatch_table;

//
// Dispatch table template. Each `IMPORT_MODULE` / `IMPORT_SYMBOL` specializes
// `dispatch_table_impl<N+1>` inheriting from `<N>`. The base case `<0>` is
// defined below; platform backends (`usermode.h`, `kernelmode.h`) provide
// the actual `init`/`destroy`/`find_module` implementations.
//

template <size_t N, typename Mode>
struct dispatch_table_impl;

template <typename Mode>
struct dispatch_table_impl<0, Mode>
  : private dispatch_table_storage<Mode>
{
    using mode = mode_traits<Mode>;

    //
    // Initialize base-level function pointers. Implemented in the platform
    // backend (e.g., `usermode.h` resolves `VirtualFree`, `LoadLibraryA`, etc.).
    //

    int init(void* argument1, void* argument2);

    //
    // Base-level teardown. Usually empty (cleanup is handled by asm).
    //

    void destroy(void* argument1, void* argument2);

protected:
    //
    // Returns `nullptr` at the base level. Overridden by `IMPORT_MODULE`
    // entries which store their resolved module handle.
    //

    void* current_module() const;

    //
    // Module/symbol resolution helpers. The platform backend provides
    // the actual implementations. `IMPORT_MODULE`/`IMPORT_SYMBOL` `init()`
    // methods call these through the inheritance chain.
    //

    void* load_module(const char* name);
    void unload_module(void* module);
    void* find_module(const char* name) const;
    void* find_module(uint32_t hash) const;

    template <typename F>
    F lookup_symbol(void* module, const char* name) const;
};

//
// Walks the dispatch table inheritance chain backwards from entry `Id`
// to find the flags of the nearest entry of a given kind.
//
// Used by `IMPORT_SYMBOL` to inherit flags from its parent module.
// For example, if `IMPORT_MODULE` has `SCFW_FLAG_DYNAMIC_RESOLVE`, all
// its child `IMPORT_SYMBOL`s pick that up automatically.
//

template <size_t Id, typename Mode, entry_kind EntryKind>
struct lookup_flags {
    static constexpr uint32_t get() {
        if constexpr (Id == 0) {
            return 0;
        }

        if constexpr (dispatch_table_impl<Id, Mode>::entry_type != EntryKind) {
            return lookup_flags<Id - 1, Mode, EntryKind>::get();
        }

        if constexpr (EntryKind == entry_kind::symbol) {
            return dispatch_table_impl<Id, Mode>::entry_flags;
        } else if constexpr (EntryKind == entry_kind::module) {
            return dispatch_table_impl<Id, Mode>::module_flags;
        }
    }

    static constexpr uint32_t value = get();
};

template <size_t Id, typename Mode, entry_kind EntryKind>
constexpr uint32_t lookup_flags_v = lookup_flags<Id, Mode, EntryKind>::value;

//
// CRTP base for callable proxies. Makes a zero-size struct behave like a
// function pointer. The Derived class must provide `get()` returning the
// actual function pointer from the dispatch table.
//
// sc::Sleep(1000)  =>  callable_Sleep::operator()(1000)
//                  =>  callable_Sleep::get()(1000)
//                  =>  __dispatch_table.slot_Sleep_(1000)
//

template <typename F, typename Derived>
struct proxy_callable;

template <typename R, typename... Args, typename Derived>
struct proxy_callable<R(*)(Args...), Derived> {
    __forceinline
    R operator()(Args... args) const {
        return static_cast<const Derived*>(this)->get()(args...);
    }
};

//
// Specialization for variadic (C-style `...`) function pointers, e.g.
// `sprintf`, `wprintf`. Uses a forwarding parameter pack to pass the
// variable arguments through to the underlying function pointer.
//

template <typename R, typename... Args, typename Derived>
struct proxy_callable<R(*)(Args..., ...), Derived> {
    template <typename... CallArgs>
    __forceinline
    R operator()(CallArgs&&... args) const {
        return static_cast<const Derived*>(this)->get()(std::forward<CallArgs>(args)...);
    }
};

#ifdef _M_IX86

//
// x86 has distinct calling conventions (`__stdcall`, `__fastcall`) which are
// different function pointer types. Need separate specializations.
//

template <typename R, typename... Args, typename Derived>
struct proxy_callable<R(__stdcall*)(Args...), Derived> {
    __forceinline
    R __stdcall operator()(Args... args) const {
        return static_cast<const Derived*>(this)->get()(args...);
    }
};

template <typename R, typename... Args, typename Derived>
struct proxy_callable<R(__fastcall*)(Args...), Derived> {
    __forceinline
    R __fastcall operator()(Args... args) const {
        return static_cast<const Derived*>(this)->get()(args...);
    }
};
#endif

//
// CRTP base for value proxies. Provides transparent read/write access
// to a value stored in the dispatch table (or a PIC-relocated global).
// The Derived class must provide `get()` returning a pointer to the value.
//
// Supports: implicit conversion (`operator T&`), assignment (`operator=`),
// address-of (`operator&`), and boolean conversion.
//

template <typename T, typename Derived>
struct proxy_value {
    using value_type = T;

    template<typename U = value_type>
    __forceinline
    operator bool() const
        requires (
            !std::is_same_v<U, bool> &&
            std::is_convertible_v<U, bool>
        )
    {
        return static_cast<bool>(*static_cast<const Derived*>(this)->get());
    }

    __forceinline
    value_type* operator&() {
        return static_cast<const Derived*>(this)->get();
    }

    __forceinline
    const value_type* operator&() const {
        return static_cast<const Derived*>(this)->get();
    }

    __forceinline
    operator value_type&() {
        return *static_cast<const Derived*>(this)->get();
    }

    __forceinline
    operator const value_type&() const {
        return *static_cast<const Derived*>(this)->get();
    }

    __forceinline
    value_type& operator=(const value_type& value) {
        return *static_cast<const Derived*>(this)->get() = value;
    }
};

} // namespace detail
} // namespace sc
