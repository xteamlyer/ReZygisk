#!/usr/bin/env bash
# INFO: The host test suite, shared by both workflows so a pull request runs
#       exactly what main runs once it merges.
#
#       The loader itself can never execute here, but the parts that fail
#       silently on a device are pure text and byte handling: the ELF reader
#       and the mini-debug decompressor behind it, the mountinfo parser that
#       decides what a revert would unmount, and the APatch package_config
#       parser that decides who gets root.
#
#       Every test pulls in the .c it exercises rather than linking against
#       it, so its static helpers are reachable; the include paths are the
#       ones those .c files expect.
set -eu

cd "$(dirname "$0")/../.."

# INFO: The loader and the daemon implement their own halves of the wire
#       protocol, and both still compile when one side drifts. This fails
#       first and cheapest, before anything is built.
python3 tests/host/check_protocol.py

# INFO: -Werror on everything written in this tree, -w on the vendored XZ
#       decompressor: it is upstream code that is not maintained here, and
#       its warnings are not actionable.
cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -Iloader/src/external/lzma \
   -c loader/src/common/elf_util.c -o /tmp/elf_util.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_lzma2.c -o /tmp/xz_lzma2.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_stream.c -o /tmp/xz_stream.o

cc -std=c18 -D_GNU_SOURCE -w \
   -DXZ_DEC_DYNALLOC=1 -DXZ_DEC_ANY_CHECK=1 -DXZ_INTERNAL_CRC32=1 \
   -DNOINLINE=noinline_for_stack \
   -Iloader/src/external/lzma \
   -c loader/src/external/lzma/xz_dec_bcj.c -o /tmp/xz_bcj.o

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include -Iloader/src/common \
   -Iloader/src/external/lzma \
   tests/host/test_elf_util.c /tmp/elf_util.o /tmp/xz_lzma2.o \
   /tmp/xz_stream.o /tmp/xz_bcj.o \
   -o /tmp/test_elf_util

python3 tests/host/make_debugdata.py /tmp/debugdata
/tmp/test_elf_util /tmp/debugdata /tmp/test_elf_util

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Iloader/src/include \
   tests/host/test_unmount.c -o /tmp/test_unmount
/tmp/test_unmount

# INFO: The same parser built the other way: the APatch flavour skips the
#       loop-device probe and matches module overlays by their /adb/modules
#       root alone, which is a different branch of carries_root_trace.
cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror -DROOT_IMPL_APATCH \
   -Itests/host -Iloader/src/include \
   tests/host/test_unmount.c -o /tmp/test_unmount_apatch
/tmp/test_unmount_apatch

cc -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror \
   -Itests/host -Izygiskd/src -Izygiskd/src/root_impl \
   tests/host/test_apatch.c -o /tmp/test_apatch
/tmp/test_apatch
