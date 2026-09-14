    .intel_syntax noprefix

#ifndef SCFW_P2ALIGN
#   define SCFW_P2ALIGN 4
#endif

#
# Externally used symbols.
#

#ifdef SCFW_ENABLE_CLEANUP
    .extern __start
#else
    .extern @_entry@8
#endif

#
# .text$00 is the very first section in the final binary.
# __init is the PE entry point (/ENTRY:_init), so it must be
# placed here to be the first instruction executed.
#
# __init stays in a plain section - it is always live and must come first.
# __pc gets its own COMDAT section so /OPT:REF can drop it in payloads
# that never call _pic().
#

    .section .text$00,"ax"

#++
#
# void
# __fastcall
# _init (
#    _In_ void* argument1,
#    _In_ void* argument2
#    )
#
# Routine Description:
#
#    PE entry point (x86). Captures the shellcode base address using
#    the call/pop trick (x86 has no LEA [eip] like x64 has LEA [rip]),
#    then jumps to __start (with cleanup) or directly to _entry
#    (without cleanup).
#
# Arguments:
#
#    argument1 - Value of ECX register (__fastcall).
#    argument2 - Value of EDX register (__fastcall).
#
# Return Value:
#
#    None.
#
#--

    .globl __init
    .p2align SCFW_P2ALIGN
__init:

#ifdef SCFW_ENABLE_CLEANUP
#
# Get the address of __init using the call/pop trick:
#   call pushes EIP+5 onto the stack (call is 5 bytes),
#   pop loads it into esi, then subtract 5 to get __init's address.
# esi is callee-preserved, so it survives until __start uses it.
#

    call    1f
1:  pop     esi                         # esi = EIP after call
    sub     esi, 5                      # esi = address of __init (call is 5 bytes)
    jmp     __start
#else
    jmp     @_entry@8
#endif

#++
#
# void*
# __cdecl
# _pc (
#    void
#    )
#
# Routine Description:
#
#    Returns the runtime address of __pc itself. x86 version uses
#    the call/pop trick since there's no RIP-relative addressing.
#    Used by _pic() to compute compile-time vs runtime delta.
#
# Return Value:
#
#    Runtime address of this function (in EAX).
#
#--

    .section .text$00,"ax",discard,__pc
    .globl __pc
    .p2align SCFW_P2ALIGN
__pc:
    call    1f
1:  pop     eax
    sub     eax, 5                          # Adjust for call instruction size
    ret

    .p2align SCFW_P2ALIGN
