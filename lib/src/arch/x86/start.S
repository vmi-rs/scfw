    .intel_syntax noprefix

#ifndef SCFW_P2ALIGN
#   define SCFW_P2ALIGN 4
#endif

#
# Externally used symbols.
#

    .extern @_entry@8
    .extern ___dispatch_table

#
# VirtualFree flags.
#

    .equ MEM_RELEASE, 0x8000

#
# .text$10 comes after __init (.text$00).
# Contains _cleanup_*, __start - the core runtime functions that
# need to be in shellcode memory (they get freed after execution).
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
# void
# __fastcall
# _cleanup_usermode (
#    void* address,
#    void* return_address
#    )
#
# Routine Description:
#
#    Frees the shellcode's own memory by tail-calling VirtualFree.
#    Called by __start after _entry returns. Uses __fastcall: ecx = address
#    to free, edx = return address (where VirtualFree should return to).
#
#    Since x86 VirtualFree is __stdcall, we manually push the args in
#    reverse order plus the return address, then jmp to VirtualFree.
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,@_cleanup_usermode@8
    .globl @_cleanup_usermode@8
    .p2align SCFW_P2ALIGN
@_cleanup_usermode@8:

#
# Get PIC-adjusted address of the dispatch table, then read VirtualFree
# from offset +4 (free_ is the second field, 4 bytes on x86).
#

    call    __pc
    sub     eax, offset __pc
    add     eax, offset ___dispatch_table

    mov     eax, [eax + 4]                  # eax = VirtualFree

#
# Set up stdcall stack frame for VirtualFree(lpAddress, 0, MEM_RELEASE).
# Push return address (edx) below the args so VirtualFree "returns" to
# the original shellcode caller.
#

    push    MEM_RELEASE                     # dwFreeType
    push    0                               # dwSize
    push    ecx                             # lpAddress
    push    edx                             # return address
    jmp     eax                             # tail call: VirtualFree(address, 0, MEM_RELEASE)

#++
#
# void
# __fastcall
# _cleanup_kernelmode (
#    void* address,
#    void* return_address
#    )
#
# Routine Description:
#
#    Kernel-mode cleanup. Same approach as _cleanup_usermode but calls
#    ExFreePool (single argument) instead of VirtualFree.
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,@_cleanup_kernelmode@8
    .globl @_cleanup_kernelmode@8
    .p2align SCFW_P2ALIGN
@_cleanup_kernelmode@8:

#
# Get PIC-adjusted address of the dispatch table, then read ExFreePool
# from offset +4.
#

    call    __pc
    sub     eax, offset __pc
    add     eax, offset ___dispatch_table

    mov     eax, [eax + 4]                  # eax = ExFreePool

    push    ecx                             # address to free
    push    edx                             # return address
    jmp     eax                             # tail call: ExFreePool(address)

#++
#
# void
# __fastcall
# _start (
#    _In_ void* argument1,
#    _In_ void* argument2
#    )
#
# Routine Description:
#
#    Main shellcode startup (x86). Saves the return address, calls
#    _entry (which initializes the dispatch table and calls the user's
#    entry function), then tail-calls _cleanup to free shellcode memory.
#
# Arguments:
#
#    argument1 - Value of ECX register (__fastcall).
#    argument2 - Value of EDX register (__fastcall).
#
#    esi = shellcode base address (set by __init, callee-preserved).
#
# Return Value:
#
#    None.
#
#--

    .section .text$10,"ax",discard,__start
    .globl __start
    .p2align SCFW_P2ALIGN
__start:

#
# Save the return address from the stack into ebx (callee-preserved).
# We'll need it later to pass to the cleanup function, so VirtualFree
# returns to the original shellcode caller.
#

    mov     ebx, [esp]

#
# Call _entry to initialize the dispatch table and run user code.
# (uses __fastcall, so ecx/edx are passed through.)
#

    call    @_entry@8

#
# Get PIC-adjusted address of the dispatch table.
#

    call    __pc
    sub     eax, offset __pc
    add     eax, offset ___dispatch_table

#
# Load cleanup_ from offset 0 of the dispatch table and tail-call it.
# ecx = shellcode base address (what to free, from esi set by __init).
# edx = original return address (saved in ebx above).
#
# Must be jmp (tail call) - after cleanup, this memory is freed.
# The cleanup function sets up the VirtualFree stdcall frame and
# jumps to VirtualFree, which returns to the original caller.
#

    mov     eax, [eax]                      # eax = __dispatch_table.cleanup_

    mov     ecx, esi                        # shellcode base address (set by __init)
    mov     edx, ebx                        # return address
    jmp     eax                             # tail call
