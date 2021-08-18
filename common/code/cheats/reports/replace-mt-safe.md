# Why are two jumps with zero offset used in this multi-threaded safe patch?

In the OpenJDK sources, file nativeInst_x86.cpp defines method [NativeCall::replace_mt_safe()](https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/hotspot/cpu/x86/nativeInst_x86.cpp#L199), which implements a multi-threaded safe patch in a lockless manner for x86 cpus, ensuring the target instruction address is cache line aligned on a (at least) 32-bit boundary ([value of BytesPerWord](https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/hotspot/share/utilities/globalDefinitions.hpp#L155)):

```c
// MT-safe patching of a call instruction.
// First patches first word of instruction to two jmp's that jmps to them
// selfs (spinlock). Then patches the last byte, and then atomicly replaces
// the jmp's with the first 4 byte of the new instruction.
void NativeCall::replace_mt_safe(address instr_addr, address code_buffer) {
  assert(Patching_lock->is_locked() ||
         SafepointSynchronize::is_at_safepoint(), "concurrent code patching");
  assert (instr_addr != NULL, "illegal address for code patching");

  NativeCall* n_call =  nativeCall_at (instr_addr); // checking that it is a call
  if (os::is_MP()) {
    guarantee((intptr_t)instr_addr % BytesPerWord == 0, "must be aligned");
  }

  // First patch dummy jmp in place
  unsigned char patch[4];
  assert(sizeof(patch)==sizeof(jint), "sanity check");
  patch[0] = 0xEB;       // jmp rel8
  patch[1] = 0xFE;       // jmp to self
  patch[2] = 0xEB;
  patch[3] = 0xFE;

  // First patch dummy jmp in place
  *(jint*)instr_addr = *(jint *)patch;

  // Invalidate.  Opteron requires a flush after every write.
  n_call->wrote(0);

  // Patch 4th byte
  instr_addr[4] = code_buffer[4];

  n_call->wrote(4);

  // Patch bytes 0-3
  *(jint*)instr_addr = *(jint *)code_buffer;

  n_call->wrote(0);

  // [...]
}
```

Why are two "jmp to self" being used instead of a single one at the beginning of the instruction address? What protections does the second jump add here?

Contrast this with the approach taken in [NativeCall::set_destination_mt_safe()](https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/hotspot/cpu/x86/nativeInst_x86.cpp#L258), which matches my expectations: patching a single jump at the beginning, then the last 3 bytes, then the first 2 bytes:

```c
// First patch dummy jump in place:
{
  u_char patch_jump[2];
  patch_jump[0] = 0xEB;       // jmp rel8
  patch_jump[1] = 0xFE;       // jmp to self

  assert(sizeof(patch_jump)==sizeof(short), "sanity check");
  *(short*)instruction_address() = *(short*)patch_jump;
}
// Invalidate.  Opteron requires a flush after every write.
wrote(0);

// (Note: We assume any reader which has already started to read
// the unpatched call will completely read the whole unpatched call
// without seeing the next writes we are about to make.)

// Next, patch the last three bytes:
u_char patch_disp[5];
patch_disp[0] = call_opcode;
*(int32_t*)&patch_disp[1] = (int32_t)disp;
assert(sizeof(patch_disp)==instruction_size, "sanity check");
for (int i = sizeof(short); i < instruction_size; i++)
  instruction_address()[i] = patch_disp[i];

// Invalidate.  Opteron requires a flush after every write.
wrote(sizeof(short));

// (Note: We assume that any reader which reads the opcode we are
// about to repatch will also read the writes we just made.)

// Finally, overwrite the jump:
*(short*)instruction_address() = *(short*)patch_disp;
// Invalidate.  Opteron requires a flush after every write.
wrote(0);
```

NativeCall::replace_mt_safe() was introduced in the first "Initial load" commit, so there's no commit log that elaborates on it. Also searched on the JDK Bug System, and while some issues reference the method, they don't explain the patch itself.
