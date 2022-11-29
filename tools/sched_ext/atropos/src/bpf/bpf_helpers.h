// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef BPF_HELPERS_H_
#define BPF_HELPERS_H_

/*
 * Earlier versions of clang/pahole lost upper 32bits in 64bit enums which can
 * lead to really confusing misbehaviors. Let's trigger a build failure.
 */
static inline void ___vmlinux_h_sanity_check___(void)
{
	_Static_assert(SCX_DSQ_FLAG_BUILTIN,
		       "bpftool generated vmlinux.h is missing high bits for 64bit enums, upgrade clang and pahole");
}

/**
 * MEMBER_VPTR - Obtain the verified pointer to a struct or array member
 * @base: struct or array to index
 * @member: dereferenced member (e.g. ->field, [idx0][idx1], ...)
 *
 * The verifier often gets confused by the instruction sequence the compiler
 * generates for indexing struct fields or arrays. This macro forces the
 * compiler to generate a code sequence which first calculates the byte offset,
 * checks it against the struct or array size and add that byte offset to
 * generate the pointer to the member to help the verifier.
 *
 * Ideally, we want to abort if the calculated offset is out-of-bounds. However,
 * BPF currently doesn't support abort, so evaluate to NULL instead. The caller
 * must check for NULL and take appropriate action to appease the verifier. To
 * avoid confusing the verifier, it's best to check for NULL and dereference
 * immediately.
 *
 *	vptr = MEMBER_VPTR(my_array, [i][j]);
 *	if (!vptr)
 *		return error;
 *	*vptr = new_value;
 */
#define MEMBER_VPTR(base, member) (typeof(base member) *)({			\
	u64 __base = (u64)base;							\
	u64 __addr = (u64)&(base member) - __base;				\
	asm volatile (								\
		"if %0 <= %[max] goto +2\n"					\
		"%0 = 0\n"							\
		"goto +1\n"							\
		"%0 += %1\n"							\
		: "+r"(__addr)							\
		: "r"(__base),							\
		  [max]"i"(sizeof(base) - sizeof(base member)));		\
	__addr;									\
})

#endif // BPF_HELPERS_H_
