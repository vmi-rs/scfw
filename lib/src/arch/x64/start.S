    .intel_syntax noprefix

#ifndef SCFW_P2ALIGN
#   define SCFW_P2ALIGN 4
#endif

#
# Externally used symbols.
#

    .extern _entry
    .extern __dispatch_table

#
# VirtualFree flags.
#

    .equ MEM_RELEASE, 0x8000

#
# .text$10 comes after _init (.text$00).
# Contains _pc, _cleanup_*, and _start - the core runtime functions
# that need to be in shellcode memory (they get freed after execution).
#
# Each routine gets its own COMDAT section, keyed on its own symbol.
# A single plain .section would place every routine in one non-COMDAT
# chunk, which /OPT:REF keeps as a GC root, so referencing any routine
# would drag in all the others. Per-symbol COMDATs are the assembly
# equivalent of -ffunction-sections and let the linker drop what the
# payload never calls (such as the unused cleanup variant).
#

#++
#
# void*
# _pc (
#    void
#    )
#
# Routine Description:
#
#    Returns the runtime address of _pc itself via RIP-relative LEA.
#    Used by _pic() to compute the delta between compile-time and
#    runtime addresses for position-independent memory access.
#
# Return Value:
#
#    Runtime address of this function (in RAX).
#
#--

    .section .text$10,"ax",discard,_pc
    .globl _pc
    .p2align SCFW_P2ALIGN
_pc:
    lea     rax, [rip + _pc]
    ret

#++
#
# void
# _cleanup_usermode (
#    void* address
#    )
#
# Routine Description:
#
#    Frees the shellcode's own memory by tail-calling VirtualFree.
#    Called by _start after _entry returns. Since this function is
#    inside the memory being freed, it must not return - it jumps
#    directly to VirtualFree, which returns to the original caller.
#
#    Reads VirtualFree from __dispatch_table.free_ (offset +8).
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,_cleanup_usermode
    .globl _cleanup_usermode
    .p2align SCFW_P2ALIGN
_cleanup_usermode:

#
#   rcx = address to free (set by _start)
#   rax = VirtualFree (from dispatch_table.free_ at offset +8)
#   rdx = 0 (dwSize, must be 0 for MEM_RELEASE)
#   r8  = MEM_RELEASE
#
#   tail call: VirtualFree(address, 0, MEM_RELEASE)
#   VirtualFree returns to whoever originally called the shellcode.
#

    mov     rax, [rip + __dispatch_table + 8]
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    jmp     rax

#++
#
# void
# _cleanup_kernelmode (
#    void* address
#    )
#
# Routine Description:
#
#    Kernel-mode cleanup. Same idea as _cleanup_usermode but calls
#    ExFreePool instead of VirtualFree (single argument: the pointer).
#    Reads ExFreePool from __dispatch_table.free_ (offset +8).
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,_cleanup_kernelmode
    .globl _cleanup_kernelmode
    .p2align SCFW_P2ALIGN
_cleanup_kernelmode:

#
#   rcx = address to free (set by _start)
#   rax = ExFreePool (from dispatch_table.free_ at offset +8)
#
#   tail call: ExFreePool(address)
#

    mov     rax, [rip + __dispatch_table + 8]
    jmp     rax

#++
#
# void
# _start (
#    _In_ void* argument1,
#    _In_ void* argument2
#    )
#
# Routine Description:
#
#    Main shellcode startup. Saves callee-preserved registers, calls
#    _entry (which initializes the dispatch table and calls the user's
#    entry function), then tail-calls _cleanup to free shellcode memory.
#
# Arguments:
#
#    argument1 - Value of RCX register (passed through to _entry/entry).
#    argument2 - Value of RDX register (passed through to _entry/entry).
#
#    r11 = shellcode base address (set by _init).
#          Stashed in r15 (callee-preserved) across the _entry call,
#          then passed to _cleanup via rcx.
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,_start
    .globl _start
    .p2align SCFW_P2ALIGN
_start:

#
# Save callee-preserved registers to the caller's shadow space.
#

    mov     [rsp + 0x08], r12
    mov     [rsp + 0x10], r13
    mov     [rsp + 0x18], r14
    mov     [rsp + 0x20], r15

#
# Allocate shadow space (32 bytes) + 8 bytes alignment = 0x28.
#

    sub     rsp, 0x28

#
# Stash the shellcode base address (from r11, set by _init) into
# r15 (callee-preserved) so it survives the _entry call.
#

    mov     r15, r11

#
# Call _entry to initialize the dispatch table and run user code.
# Using lea+call instead of a direct call to stay position-independent.
#

    lea     r13, [rip + _entry]
    call    r13

#
# Grab the shellcode base address from r15 into rcx (first arg for
# cleanup) BEFORE restoring the caller's r15. None of the register
# restores below touch rcx, so it survives to the tail call.
#

    mov     rcx, r15

#
# Tear down the stack frame and restore callee-preserved registers.
#

    add     rsp, 0x28
    mov     r15, [rsp + 0x20]
    mov     r14, [rsp + 0x18]
    mov     r13, [rsp + 0x10]
    mov     r12, [rsp + 0x08]

#
# Load cleanup_ from offset 0 of the dispatch table and tail-call it.
# rcx = shellcode base address (already set above).
#
# This MUST be a jmp (tail call), not a call. After cleanup runs,
# the shellcode memory (including this function) will be freed.
# VirtualFree returns to whoever originally invoked the shellcode.
#

    mov     rax, [rip + __dispatch_table]
    jmp     rax
