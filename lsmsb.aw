<!DOCTYPE html>
<html>
  <head>
    <title>LSMSB</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <link href="style.css" rel="stylesheet" charset="utf-8">
  </head>

  <body>
    <h1>LSMSB: A Linux Sandboxing Scheme</h1>

<p>Adam Langley (<tt>agl@google.com</tt>)<br>
Version <tt>20090606</tt></p>

@@TOC

<p>This is LSMSB, a sandboxing scheme for Linux based on the ideas of the <a
href="http://www.318.com/techjournal/security/a-brief-introduction-to-mac-os-x-sandbox-technology/">
OS X sandbox</a> (which, in turn, was inspired by TrustedBSD and FreeBSD).</p>

<p>Imagine that you're working on a university computer and you get a binary
which promises to do some fiendishly complex calculation, reading from a file
<tt>./input</tt> and writing to a file <tt>./output</tt>. It also talks to a
specific server to access a pre-computed lookup table. You want to run it, but
you don't want to have to trust that it won't do anything malicious (save
giving the wrong answer).</p>

<p>You current options are very limited. Without root access you cannot setup a
chroot jail, as troublesome as that is. If the system has SELinux or AppArmor
installed, the tools are there but those are MAC systems and only root can
define their policies.</p>

<p>Your best bet, currently, is either to use <tt>ptrace</tt> or to run a whole
virtual machine. The former is slow and difficult to get right in the face of
threads and the latter is a sledgehammer when we just want to crack a nut.</p>

<p>To address these concerns we need a sandboxing system which is:</p>

<ol>
<li>Available: The sandbox must be available to normal users. MAC systems
which are only configured by root are not the correct solution for this.</li>
<li>Flexible: <tt>seccomp</tt> is (currently) too rigid to really be useful. A
sandbox must be able to express the correct level of authority.</li>
<li>Reliable: The sandbox should not be open to races etc.</li>
<li>Deployable: One should be able to use a sandbox via a couple of call in
<tt>main</tt>(). If you have to implement an IPC system and pass file descriptors around
in order to achieve reliability then that's a significant demerit.</li>
<li>Composable: If I choose to impose a sandbox on a process before <tt>exec</tt>()
then that process should still be able to impose another sandbox on itself. The
resulting authority should be the intersection of the two sandboxes.</li>
<li>Affordable: It should be reasonable to sandbox many processes. If the
sandbox has a high performance impact, then that's a problem. If the sandbox
requires a tracing process for every sandboxed process, then that's a
problem.</li>
</ol>

<p>We present a sandboxing scheme using the LSM hooks in the Linux kernel. At
the moment this scheme is a prototype only and this code is based off of
2.6.30-rc<i>x</i>.</p>

@/* Kernel code

<div style="float:left; padding-right: 1em;"><object width="212" height="200" data="dia1.svg" type="image/svg+xml" class="img"></object></div>

<p>LSMSB uses the Linux Security Modules hooks to intercept security decisions in
the kernel. The policies are implemented by tables of rules which are uploaded
from user-space. Each process has a stack of zero or more sandboxes. Each
sandbox may define a rule table for a given operation. An action must be
accepted by all the sandboxes in the stack for it to be permitted. Child
processes inherit the sandbox stack of their parents and are free to push extra
sandboxes onto their stack. By construction, this can only reduce their
authority.</p>

<div style="clear: left;"></div>

@<Sandbox structure@>=

struct lsmsb_sandbox {
        atomic_t refcount;
        struct lsmsb_sandbox *parent;
        struct lsmsb_filter *dentry_open;
        // TODO: add support for more actions
};

@/ Rule tables

<p>An LSMSB filter evaluates a table of rules to decide if a given action is
permitted or not. The table of rules is specific to a given filter as the
filter defines the context in which the table is evaluated. The context
determines which arguments are provided to the table, their order, syntax and
semantics. It also defines the meaning of the return code although, by
convention, zero always means reject and non-zero means accept.</p>

<p>The rule tables are very limited. Conditionals do exist, but a rule can only
jump forward, thus there are no loops. This also means that the rule tables are
not Turing complete and are guaranteed to terminate.</p>

<h5>The filter structure</h5>

<p>Each rule in the table is a single 32-bit unsigned integer. Because constant
values often don't fit in 32-bits, we need another way to deal with them.  Thus
constants are kept in a side array, linked with each filter.  The rules in the
table can reference them by their index.</p>

<p>For working storage, the rules in the table have an array of 16 registers which
can either store a 32-bit unsigned integer or a byte-string (which is a normal
string, but may contain NUL characters). If a table is exceedingly complex, it
may need more than 16-registers of storage to hold temporary values. For these
situations, we also allow the table to specify the number of spill slots
that it needs. Spill slots act just like registers except that they have to be
read and written explicitly.</p>

<p>From this, the structure for a filter is obvious:</p>

@<Filter structure@>=
struct lsmsb_filter {
	unsigned num_operations;
	unsigned num_spill_slots;
	unsigned num_constants;
	uint32_t *operations;
	struct lsmsb_value constants[0];
};

#define LSMSB_NUM_REGISTERS 16
// This is the maximum number of operations in a filter. Note that the code
// assumes that this value fits in a uint16_t with a couple of values to spare.
#define LSMSB_FILTER_OPS_MAX 32768
#define LSMSB_SPILL_SLOTS_MAX 32
#define LSMSB_CONSTANTS_MAX 256
#define LSMSB_CONSTANT_LENGTH_MAX 512

@/ Filter values

<p>
  The contents of registers, spill slots and constants are all &lsquo;values&rsquo;. These
  values are either a 32-bit unsigned int or a bytestring and represented by the
  following structure.
</p>

<p>
  For integer values, <tt>value</tt> is the integer and <tt>data</tt> is set to <tt>NULL</tt>. For
  bytestrings, <tt>data</tt> is a pointer to the bytes (and thus not <tt>NULL</tt>) and <tt>value</tt>
  is the number of bytes.
</p>

@<Value structure@>=
struct lsmsb_value {
	uint8_t *data;
	uint32_t value;
};

@/ Operations

<p>
  Each rule in the table consists of at least an operation, which is encoded in
  the top 8-bits. Given the operation, there are often other arguments (register
  numbers etc) encoded in the remaining 24-bits, the format of which is specific
  to each operation.
</p>

<p>
  The operations are numbered from zero by the following enum:
</p>

<table>
  <tr><th>Name</th><th>Explanation</th><th>Effect</th></tr>

  <tr><td><tt>MOV</tt></td> <td>Move</td> <td>reg<sub>1</sub> = reg<sub>2</sub></td></tr>
  <tr><td><tt>LDI</tt></td> <td>Load immediate</td> <td>reg<sub>1</sub> = immediate value</td></tr>
  <tr><td><tt>LDC</tt></td> <td>Load constant</td> <td>reg<sub>1</sub> = constant value</td></tr>
  <tr><td><tt>RET</tt></td> <td>Return value in register</td> <td><i>terminates the filter</i></td></tr>
  <tr><td><tt>JMP</tt></td> <td>Jump</td> <td>Skips the next <i>n</i> rules</td></tr>
  <tr><td><tt>SPILL</tt></td> <td>Spill register</td> <td>spill<sub>1</sub> = reg<sub>1</sub></td></tr>
  <tr><td><tt>UNSPILL</tt></td> <td>Unspill register</td> <td>reg<sub>1</sub> = spill<sub>1</sub></td></tr>
  <tr><td><tt>JC</tt></td> <td>Jump conditionally</td> <td>If reg<sub>1</sub> &gt; 0 then skip the next <i>n</i> rules</td></tr>
  <tr><td><tt>EQ</tt></td> <td>Equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> == reg<sub>3</sub></td></tr>
  <tr><td><tt>GT</tt></td> <td>Greater than?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &gt; reg<sub>3</sub></td></tr>
  <tr><td><tt>LT</tt></td> <td>Less than?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &lt; reg<sub>3</sub></td></tr>
  <tr><td><tt>GTE</tt></td> <td>Greater than or equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &gt;= reg<sub>3</sub></td></tr>
  <tr><td><tt>LTE</tt></td> <td>Less than or equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &lt;= reg<sub>3</sub></td></tr>
  <tr><td><tt>AND</tt></td> <td>Bitwise conjunction</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &amp; reg<sub>3</sub></td></tr>
  <tr><td><tt>OR</tt></td> <td>Bitwise disjunction</td> <td>reg<sub>1</sub> = reg<sub>2</sub> | reg<sub>3</sub></td></tr>
  <tr><td><tt>XOR</tt></td> <td>Bitwise exclusive-or</td> <td>reg<sub>1</sub> = reg<sub>2</sub> ^ reg<sub>3</sub></td></tr>
  <tr><td><tt>ISPREFIXOF</tt></td> <td>Bytestring prefix</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &sube; reg<sub>3</sub></td></tr>
</table>

@<List of operations@>=
enum lsmsb_opcode {
	LSMSB_OPCODE_MOV = 0,
	LSMSB_OPCODE_LDI,
	LSMSB_OPCODE_LDC,
	LSMSB_OPCODE_RET,
	LSMSB_OPCODE_JMP,
	LSMSB_OPCODE_SPILL,
	LSMSB_OPCODE_UNSPILL,
	LSMSB_OPCODE_JC,
	LSMSB_OPCODE_EQ,
	LSMSB_OPCODE_GT,
	LSMSB_OPCODE_LT,
	LSMSB_OPCODE_GTE,
	LSMSB_OPCODE_LTE,
	LSMSB_OPCODE_AND,
	LSMSB_OPCODE_OR,
	LSMSB_OPCODE_XOR,
	LSMSB_OPCODE_ISPREFIXOF,
};

@/ Available filter types

<p>The type of a filter signifies the operation which it intends to filter, as
well as the context that it runs in. (See <a href="@@cite:Filter structure@@">above</a>). Here are the currently defined filters.</p>

<table>
  <tr><th>Name</th> <th>Explanation</th> <th>Arguments</th></tr>

  <tr><td><tt>DENTRY_OPEN</tt></td> <td>File open</td> <td>Filename(<i>bs</i>) and mode(<i>i</i>)</td></tr>
</table>

@<Filter codes@>=
enum lsmsb_filter_code {
	LSMSB_FILTER_CODE_DENTRY_OPEN = 0,
	LSMSB_FILTER_CODE_MAX,  // not a real filter code
};

@/** Typechecking.

<p>
  The rule tables are simple enough that they can be validated such that we can
  know they they can never cause a run-time error. This is helpful as it means
  that we can pay the verification cost once (when loading the table) and omit
  run-time checks when evaluating.
</p>

@<Typechecking@>=

@<Predecessor table utility functions@>

@<Predecessor tables@>

@<Type unification@>

@<Typecheck function@>

@/ Predecessor tables

<p>
  For each rule in the table there is a set of rules which can be the immediate
  predecessor of that rule. In the simple case, the rule preceding will fall
  though and be the single predecessor. In more complex cases, a rule might be
  the target of several jumps and a fall though.
</p>

<p>
  The predecessor table conceptually has <i>n</i> rows and <i>x</i> columns, where <i>n</i> is
  the number of rules in the rule table and <i>x</i> is a constant value. If we didn't
  have jumps each rule could only have a single predecessor, <i>x</i> could be one,
  and we would have a simple array. However, in the presence of jumps <i>x</i> may
  need to be greater than one.
</p>

<p>
  In the pessimal case, every rule in the table except the last is a jump to the
  very last one. Then <i>x</i> would need to be <i>n - 1</i>, even though most of
  the slots in the table would be unused. Therefore we take a hybrid approach. We
  define <i>x</i> to be a small number and, if a row overflows, we mark it with a
  magic value. Most of the time this will work fine but, in exceptional cases,
  we have to deal with the overflows.
</p>


<div style="text-align: center;"><object width="420" height="175" data="dia2.svg" type="image/svg+xml" class="img"></object></div>

@<Predecessor tables@>=

/* This is the magic unset value in the predecessor table. This value must be
 * all ones because we clear the table with a memset. */
#define LSMSB_PREDECESSOR_TABLE_INVAL 0xffff
/* This is a magic value in the predecessor table which marks an overflow. */
#define LSMSB_PREDECESSOR_TABLE_OVERFLOW (LSMSB_FILTER_OPS_MAX + 1)
/* This is the number of predecessors that we record, per row, before
 * overflowing */
#define LSMSB_PREDECESSOR_TABLE_WIDTH 2

@<Appending to a predecessor table row@>

@<Building the predecessor table@>

@/ Appending to a predecessor table row

<p>
  Appending to a row simply involves scanning the entries in the row until a
  free slot is found. If we don't find a free slot we mark the first entry in the
  row with the magic overflow tag.
</p>

@<Appending to a predecessor table row@>=
static void lsmsb_predecessor_table_append(uint16_t *ptable, unsigned target,
					   unsigned source)
{
	uint16_t *row = &ptable[target * LSMSB_PREDECESSOR_TABLE_WIDTH];
	unsigned i;

	for (i = 0; i < LSMSB_PREDECESSOR_TABLE_WIDTH; ++i) {
		if (row[i] == LSMSB_PREDECESSOR_TABLE_OVERFLOW)
			return;  // this is already an overflow row
		if (row[i] == LSMSB_PREDECESSOR_TABLE_INVAL) {
			row[i] = source;
			return;
		}
	}

	/* we reached the end of the table without a spare slot. We have to mark
	   the row as overflowed. */
	row[0] = LSMSB_PREDECESSOR_TABLE_OVERFLOW;
}

@/ Building the predecessor table

<p>
  We build the predecessor table by first clearing it then, for each rule, we
  find its one or two successor instructions and mark it as a predecessor for
  those instructions.
</p>

@<Building the predecessor table@>=
static char lsmsb_predecessor_table_fill(uint16_t *ptable, const uint32_t *ops, unsigned num_ops)
{
	unsigned i;

	if (num_ops == 0)
		return 1;

	@<Clear the predecessor table@>

	/* First we deal with all the elements except the last. */
	for (i = 0; i < num_ops - 1; ++i) {
		const uint32_t op = ops[i];
		const enum lsmsb_opcode opcode = lsmsb_op_opcode_get(op);

		if (lsmsb_opcode_falls_through(opcode))
			lsmsb_predecessor_table_append(ptable, i + 1, i);
		if (lsmsb_opcode_is_jump(opcode)) {
			/* 0 <= i, jumplength <= 0xffff */
			const unsigned target = i + lsmsb_op_jump_length(op);
			if (target == i)
				return 0;  /* zero length jump */
			if (target >= num_ops)
				return 0;  /* tried to jump off the end */
			lsmsb_predecessor_table_append(ptable, target, i);
		}
	}

	/* Now deal with the last operation. */
	if (lsmsb_op_opcode_get(ops[num_ops - 1]) != LSMSB_OPCODE_RET)
		return 0;

	return 1;
}

@/ Clearing the predecessor table

<p>
  Since we chose our magic unused value to be <tt>0xffff</tt>, we can clear the table
  using <tt>memset</tt>.
</p>

@<Clear the predecessor table@>=
	memset(ptable, 0xff, sizeof(uint16_t) * num_ops * LSMSB_PREDECESSOR_TABLE_WIDTH);

@/ Type unification

<p>
  Type unification is the process of finding, for each rule, the set of possible
  types for each register and spill slot. Since we only have two types (integers
  and bytestrings), we can encode this using only a couple of bits.
</p>

<p>
  If we then find a rule which is going to operate on a register which could
  possibly hold the wrong type, we reject the rule table.
</p>

@<Type unification@>=

@<lsmsb_type@>

@<Type vector utility functions@>

@<is_predecessor_of@>

@<Type vector unification@>

@<Type vector updating@>

@<Type vector arrays@>

@<Filter contexts@>

@<type_vector_for_filter@>

@/ Type vectors

<p>
  A <i>type vector</i> is an array of 2-bit values, one for each register and
  spill slot. Each 2-bit value is either:
</p>

<table>
  <tr><td>Undefined:</td> <td>at the start of evaluation, every spill slot and register
which isn't defined by the context has an undefined type.</td></tr>
  <tr><td>Integer:</td> <td>an integer type.</td></tr>
  <tr><td>Bytestring:</td> <td>a byte-string type.</td></tr>
  <tr><td>Conflicting:</td> <td>the type differs depending on the control flow.</td></tr>
</table>

@<lsmsb_type|<tt>lsmsb_type</tt>@>=

enum lsmsb_type {
	LSMSB_TYPE_UNDEF = 0,
	LSMSB_TYPE_U32,
	LSMSB_TYPE_BYTESTRING,
	LSMSB_TYPE_CONFLICTING,
};

static inline char lsmsb_type_is_value(enum lsmsb_type type)
{
	return type == LSMSB_TYPE_U32 || type == LSMSB_TYPE_BYTESTRING;
}

static inline enum lsmsb_type lsmsb_constant_type_get(const struct lsmsb_value *v)
{
	return v->data ? LSMSB_TYPE_BYTESTRING : LSMSB_TYPE_U32;
}

@/ Unifying type vectors

<p>
  Given two type vectors (say, the type vectors from the two predecessors of a
  rule), we unify them by considering each element of each vector, pairwise.
  Then, for each pair, if they match then we output that value, otherwise, we
  record the value as conflicting.
</p>

<p>
  To implement this quickly, we try to operate on many elements concurrently.
  Most of the time a rule table will not use spill slots so the type vector will
  be 2 &times; 16 = 32 bits long and we can do them all in one go.
</p>

<p>
  To understand the code below, consider a single pair of 2-bit inputs. If we
  exclusive-or them, we'll end up with a true bit in the result iff the inputs
  differed. If we could map 01, 10, and 11 to 11 and then OR with the original
  input, that would map equal inputs to themselves and differing inputs to
  <tt>LSMSB_TYPE_CONFLICTING</tt>. (Remember that
  <tt>LSMSB_TYPE_CONFLICTING</tt> <a href="@@cite:lsmsb_type@@">has a value of
  11</a> in binary).
</p>

<p>
  In order to transform the exclusive-or output we define <tt>left</tt> to be the left
  bit and <tt>right</tt> to be the right bit. Then we OR together <tt>left</tt>,
  <tt>right</tt>, <tt>left &gt;&gt; 1</tt> and <tt>right &lt;&lt; 1</tt>. This
  results in the desired mapping.
</p>

<p>
  We work with 32-bit quantities where possible and fall back to 8-bit values
  otherwise. Although the type vector might not be a multiple of 4 values long,
  we still operate on the undefined bits at the end because it's harmless and
  faster.
</p>

@<Type vector unification@>=

static void lsmsb_type_vector_unify(uint8_t *a, const uint8_t *b, unsigned bytelen)
{
	unsigned offset = 0;
	while (bytelen >= 4) {
		uint32_t u = *((uint32_t *) (a + offset));
		uint32_t v = *((uint32_t *) (b + offset));
		uint32_t x = u ^ v;
		uint32_t left = x & 0xaaaaaaaau, right = x & 0x55555555;
		uint32_t result = (left | (left >> 1)) | (right | (right << 1));
		*((uint32_t *) (a + offset)) |= result;

		offset += 4;
		bytelen -= 4;
	}

	while (bytelen) {
		uint8_t u = a[offset];
		uint8_t v = b[offset];
		uint8_t x = u ^ v;
		uint32_t left = x & 0xaa, right = x & 0x55;
		uint32_t result = (left | (left >> 1)) | (right | (right << 1));
		a[offset] |= result;

		offset++;
		bytelen--;
	}
}

@/ Updating the type vectors for an operation

<p>
  Each operation may require certain types as inputs and may mutate the type of
  outputs. We model this in a function which operates on type vectors.
</p>

<p>
  At any point, if an operation would encounter a type error, we return 0.
</p>

@<Type vector updating@>=

static char lsmsb_op_type_vector_update(uint8_t *tv, uint32_t op,
					const struct lsmsb_value *constants,
					unsigned num_constants,
					unsigned num_spills) {
	const enum lsmsb_opcode opcode = lsmsb_op_opcode_get(op);
	unsigned reg1, reg2, reg3;
	enum lsmsb_type type1, type2, type3;
	unsigned c1, s1;

	switch (opcode) {
	case LSMSB_OPCODE_MOV:
		reg1 = lsmsb_op_reg1_get(op);
		reg2 = lsmsb_op_reg2_get(op);
		type2 = lsmsb_type_vector_reg_get(tv, reg2);
		if (!lsmsb_type_is_value(type2))
			return 0;
		lsmsb_type_vector_reg_set(tv, reg1, type2);
		return 1;
	case LSMSB_OPCODE_LDI:
		reg1 = lsmsb_op_reg1_get(op);
		lsmsb_type_vector_reg_set(tv, reg1, LSMSB_TYPE_U32);
		return 1;
	case LSMSB_OPCODE_LDC:
		reg1 = lsmsb_op_reg1_get(op);
		c1 = lsmsb_op_constant1_get(op);
		if (c1 >= num_constants)
			return 0;
		type1 = lsmsb_constant_type_get(&constants[c1]);
		lsmsb_type_vector_reg_set(tv, reg1, type1);
		return 1;
	case LSMSB_OPCODE_RET:
		reg1 = lsmsb_op_reg1_get(op);
		if (lsmsb_type_vector_reg_get(tv, reg1) != LSMSB_TYPE_U32)
			return 0;
		return 1;
	case LSMSB_OPCODE_JMP:
		return 1;
	case LSMSB_OPCODE_SPILL:
		s1 = lsmsb_op_spill1_get(op);
		if (s1 >= num_spills)
			return 0;
		reg1 = lsmsb_op_reg3_get(op);
		type1 = lsmsb_type_vector_reg_get(tv, reg1);
		if (!lsmsb_type_is_value(type1))
			return 0;
		lsmsb_type_vector_spill_set(tv, s1, type1);
		return 1;
	case LSMSB_OPCODE_UNSPILL:
		reg1 = lsmsb_op_reg1_get(op);
		s1 = lsmsb_op_spill2_get(op);
		if (s1 >= num_spills)
			return 0;
		type1 = lsmsb_type_vector_spill_get(tv, s1);
		if (!lsmsb_type_is_value(type1))
			return 0;
		lsmsb_type_vector_reg_set(tv, reg1, type1);
		return 1;
	case LSMSB_OPCODE_JC:
		reg1 = lsmsb_op_reg1_get(op);
		if (lsmsb_type_vector_reg_get(tv, reg1) != LSMSB_TYPE_U32)
			return 0;
		return 1;
	case LSMSB_OPCODE_EQ:
	case LSMSB_OPCODE_GT:
	case LSMSB_OPCODE_LT:
	case LSMSB_OPCODE_GTE:
	case LSMSB_OPCODE_LTE:
	case LSMSB_OPCODE_AND:
	case LSMSB_OPCODE_OR:
	case LSMSB_OPCODE_XOR:
		reg1 = lsmsb_op_reg1_get(op);
		reg2 = lsmsb_op_reg2_get(op);
		reg3 = lsmsb_op_reg3_get(op);
		type2 = lsmsb_type_vector_reg_get(tv, reg2);
		type3 = lsmsb_type_vector_reg_get(tv, reg3);
		if (type2 != LSMSB_TYPE_U32 || type3 != LSMSB_TYPE_U32)
			return 0;
		lsmsb_type_vector_reg_set(tv, reg1, LSMSB_TYPE_U32);
		return 1;
	case LSMSB_OPCODE_ISPREFIXOF:
		reg1 = lsmsb_op_reg1_get(op);
		reg2 = lsmsb_op_reg2_get(op);
		reg3 = lsmsb_op_reg3_get(op);
		type2 = lsmsb_type_vector_reg_get(tv, reg2);
		type3 = lsmsb_type_vector_reg_get(tv, reg3);
		if (type2 != LSMSB_TYPE_BYTESTRING ||
		    type3 != LSMSB_TYPE_BYTESTRING)
			return 0;
		lsmsb_type_vector_reg_set(tv, reg1, LSMSB_TYPE_U32);
		return 1;
	default:
		return 0;
	}
}

@/ Type vector arrays

<p>
  A <i>type vector array</i> is a simply an array of type vectors, one for each
  operation in the rule table. We can build a type vector array by iterating over
  the operations, unifying the type vectors for all predecessors and then
  updating the type vector for that operation.
</p>

<p>
  By the end we will have either found a type error or proved that evaluating the
  rule table will not encounter any run-time errors.
</p>

@<Type vector arrays@>=

static char lsmsb_type_vector_array_fill(uint8_t *tva,
					 const uint16_t *ptable,
					 const uint8_t *context_tv,
					 const struct lsmsb_filter *filter) {
	const unsigned tva_width = lsmsb_filter_tva_width(filter);
	const uint32_t *ops = filter->operations;
	unsigned i, j;

	if (filter->num_operations == 0)
		return 1;

	memset(tva, 0, tva_width);  /* set the first row to LSMSB_TYPE_UNDEF */
	memcpy(tva, context_tv, LSMSB_NUM_REGISTERS / 4);

	if (!lsmsb_op_type_vector_update(tva, ops[0], filter->constants,
					 filter->num_constants,
					 filter->num_spill_slots)) {
		return 0;
	}

	for (i = 1; i < filter->num_operations; ++i) {
		const uint16_t *ptable_row =
			&ptable[i * LSMSB_PREDECESSOR_TABLE_WIDTH];
		uint8_t *tva_row = tva + i * tva_width;
		char found_predecessor = 0;

		if (ptable_row[0] == LSMSB_PREDECESSOR_TABLE_OVERFLOW) {
			@<handle overflowed row@>
		} else {
			@<handle normal row@>
		}

		if (!lsmsb_op_type_vector_update(tva_row, ops[i],
						 filter->constants,
						 filter->num_constants,
						 filter->num_spill_slots)) {
			return 0;
		}
	}

	return 1;
}

@/ Unifying normal rows

<p>
  With a row where the predecessor table didn't overflow, we can easily find the
  predecessor operations. For the first one, we need to copy its type vector. For
  all subsequent predecessors, we unify the current type vector with their
  type vector.
</p>

<p>
  Here we also deal with the case of an operation with no predecessor. This can
  only occur if no control flow path leads to it. In this case, we reject the
  rule table. We assume that the tools used to generate the rule tables are
  sufficiently smart to remove dead code and we don't want to waste kernel memory
  keeping it around.
</p>

@<handle normal row@>=
	for (j = 0; j < LSMSB_PREDECESSOR_TABLE_WIDTH; ++j) {
		const unsigned p = ptable_row[j];
		const uint8_t *tva_row_p = tva + p * tva_width;
		if (p == LSMSB_PREDECESSOR_TABLE_INVAL)
			break;
		if (!found_predecessor) {
			memcpy(tva_row, tva_row_p, tva_width);
			found_predecessor = 1;
			continue;
		}

		lsmsb_type_vector_unify(tva_row, tva_row_p,
					tva_width);
	}

	if (!found_predecessor)
		return 0;  // Dead code.

@/ Unifying overflow rows

<p>
  When the predecessor table is marked as overflowed, we have to find all the
  predecessors ourselves. We can do this by checking all previous operations for
  jumps to the current operation and checking the previous instruction for fall
  though. (Recall that we only have forward jumps.)
</p>

@<handle overflowed row@>=
	for (j = 0; j < i; ++j) {
		if (lsmsb_op_is_predecessor_of(ops, j, i)) {
			if (!found_predecessor) {
				memcpy(tva_row,
				       tva + j * tva_width,
				       tva_width);
				found_predecessor = 1;
				continue;
			}

			lsmsb_type_vector_unify(
				tva_row,
				tva + j * tva_width,
				tva_width);
		}
	}

	if (!found_predecessor)
		return 0;  // shouldn't ever happen

@/ Testing for predecessor rules

@<is_predecessor_of|Predecessor testing function@>=
static char lsmsb_op_is_predecessor_of(const uint32_t *ops, unsigned i,
                                       unsigned target) {
	const uint32_t op = ops[i];
	const enum lsmsb_opcode opcode = lsmsb_op_opcode_get(op);
	
	if (i == target - 1 &&
	    lsmsb_opcode_falls_through(opcode)) {
		return 1;
	}

	if (lsmsb_opcode_is_jump(opcode) &&
	    lsmsb_op_jump_length(op) + i == target) {
		return 1;
	}

	return 0;
}

@/ Type vector utility functions

@<Type vector utility functions@>=

static inline unsigned lsmsb_filter_tva_width(const struct lsmsb_filter *filter)
{
	return (LSMSB_NUM_REGISTERS + filter->num_spill_slots + 3) / 4;
}

static inline enum lsmsb_type lsmsb_type_vector_reg_get(uint8_t *vector, unsigned reg)
{
	const unsigned byte = reg >> 2;
	const unsigned index = reg & 3;

	return (enum lsmsb_type) ((vector[byte] >> (6 - (index * 2))) & 3);
}

static inline enum lsmsb_type lsmsb_type_vector_spill_get(uint8_t *vector, unsigned slot)
{
	return lsmsb_type_vector_reg_get(vector, slot + LSMSB_NUM_REGISTERS);
}

static inline void lsmsb_type_vector_reg_set(uint8_t *vector, unsigned reg,
                                             enum lsmsb_type newtype)
{
	const unsigned byte = reg >> 2;
	const unsigned index = reg & 3;
	static const uint8_t masks[4] = { 0x3f, 0xcf, 0xf3, 0xfc };
	const uint8_t new_value = (vector[byte] & masks[index]) |
	                          newtype << (6 - (index * 2));
	vector[byte] = new_value;
}

static inline void lsmsb_type_vector_spill_set(uint8_t *vector, unsigned slot,
                                               enum lsmsb_type newtype)
{
	lsmsb_type_vector_reg_set(vector, slot + LSMSB_NUM_REGISTERS, newtype);
}

@/ Bringing typechecking together

<p>
  Pulling together the above code is straight-forward. We allocate memory for the
  predecessor table and type vector array and generate them both. If we manage to
  generate them both and the rule table checks out, then we're done.
</p>

@<Typecheck function@>=

int lsmsb_filter_typecheck(const struct lsmsb_filter *filter,
			   const uint8_t *context_type_vector)
{
	const unsigned tva_width = lsmsb_filter_tva_width(filter);
	uint16_t *predecessor_table;
	uint8_t *type_vector_array;
	int return_code = -EINVAL;

	predecessor_table = (uint16_t*) kmalloc(
		filter->num_operations *
		LSMSB_PREDECESSOR_TABLE_WIDTH *
		sizeof(uint16_t), GFP_KERNEL);
	if (!predecessor_table)
		return -ENOMEM;
	type_vector_array = kmalloc(filter->num_operations *
				    tva_width, GFP_KERNEL);
	if (!type_vector_array) {
		kfree(predecessor_table);
		return -ENOMEM;
	}

	if (!lsmsb_predecessor_table_fill(predecessor_table, filter->operations,
					  filter->num_operations)) {
		goto exit;
	}

	if (!lsmsb_type_vector_array_fill(type_vector_array, predecessor_table,
					  context_type_vector, filter)) {
		goto exit;
	}

	return_code = 0;

exit:
	kfree(type_vector_array);
	kfree(predecessor_table);
	return return_code;
}

@/** Evaluating filters

<p>Since typechecking has eliminated most run-time errors from the filter, the
evaluation of filters can happen without many of those checks.</p>

<p>The evaluation is straight-forward: a register machine is simulated with
with the register values in an array on the stack. Each instruction is
dispatched using a switch. There are several pieces of low-hanging fruit that
could make this code faster but, for now, we choose the simplest code that
works.</p>

@<Evaluating filters@>=
char lsmsb_filter_run(const struct lsmsb_filter *filter,
		      const struct lsmsb_value *init_values,
		      unsigned num_init_values)
{
	unsigned ip = 0;
	struct lsmsb_value regs[LSMSB_NUM_REGISTERS];
	struct lsmsb_value *spills = NULL;
	uint32_t op;
	enum lsmsb_opcode opcode;
	unsigned reg1, reg2, reg3, c1, s1;
	unsigned imm;
	char return_value, returned = 0;

	memcpy(regs, init_values, num_init_values * sizeof(struct lsmsb_value));

	if (filter->num_spill_slots) {
		spills = kmalloc(sizeof(struct lsmsb_value) *
				 filter->num_spill_slots, GFP_ATOMIC);
		if (!spills) {
			printk("lsmsb: failed to allocate %u spill slots\n",
			       filter->num_spill_slots);
			return 0;
		}
	}

	for (ip = 0; !returned; ++ip) {
		op = filter->operations[ip];
		opcode = lsmsb_op_opcode_get(op);

		switch (opcode) {
		case LSMSB_OPCODE_MOV:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			memcpy(&regs[reg1], &regs[reg2],
			       sizeof(struct lsmsb_value));
			break;
		case LSMSB_OPCODE_LDI:
			reg1 = lsmsb_op_reg1_get(op);
			imm = lsmsb_op_imm_get(op);
			lsmsb_value_u32_set(&regs[reg1], imm);
			break;
		case LSMSB_OPCODE_LDC:
			reg1 = lsmsb_op_reg1_get(op);
			c1 = lsmsb_op_constant1_get(op);
			memcpy(&regs[reg1], &filter->constants[c1],
			       sizeof(struct lsmsb_value));
			break;
		case LSMSB_OPCODE_RET:
			reg1 = lsmsb_op_reg1_get(op);
			return_value = regs[reg1].value > 0;
			returned = 1;
			break;
		case LSMSB_OPCODE_JMP:
			ip--;
			ip += lsmsb_op_jump_length(op);
			break;
		case LSMSB_OPCODE_SPILL:
			s1 = lsmsb_op_spill1_get(op);
			reg1 = lsmsb_op_reg3_get(op);
			memcpy(&spills[s1], &regs[reg1],
			       sizeof(struct lsmsb_value));
			break;
		case LSMSB_OPCODE_UNSPILL:
			reg1 = lsmsb_op_reg1_get(op);
			s1 = lsmsb_op_spill2_get(op);
			memcpy(&regs[reg1], &spills[s1],
			       sizeof(struct lsmsb_value));
			break;
		case LSMSB_OPCODE_JC:
			reg1 = lsmsb_op_reg1_get(op);
			if (regs[reg1].value) {
				ip--;
				ip += lsmsb_op_jump_length(op);
			}
			break;
		case LSMSB_OPCODE_EQ:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value == regs[reg3].value;
			break;
		case LSMSB_OPCODE_GT:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value > regs[reg3].value;
			break;
		case LSMSB_OPCODE_LT:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value < regs[reg3].value;
			break;
		case LSMSB_OPCODE_GTE:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value >= regs[reg3].value;
			break;
		case LSMSB_OPCODE_LTE:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value <= regs[reg3].value;
			break;
		case LSMSB_OPCODE_AND:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value & regs[reg3].value;
			break;
		case LSMSB_OPCODE_OR:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value | regs[reg3].value;
			break;
		case LSMSB_OPCODE_XOR:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].value = regs[reg2].value ^ regs[reg3].value;
			break;
		case LSMSB_OPCODE_ISPREFIXOF:
			reg1 = lsmsb_op_reg1_get(op);
			reg2 = lsmsb_op_reg2_get(op);
			reg3 = lsmsb_op_reg3_get(op);
			regs[reg1].data = NULL;
			if (regs[reg2].value > regs[reg3].value) {
				regs[reg1].value = 0;
			} else {
				regs[reg1].value =
				    memcmp(regs[reg2].data, regs[reg3].data,
					   regs[reg2].value) == 0;
			}
			break;
		default:
			// should never hit this
			returned = 1;
			return_value = 0;
			break;
		}
	}

	if (spills)
		kfree(spills);

	return return_value;
}

@/ Utility functions

<P>
  We used a few utility functions in this code which we'll now flesh out.
</P>

@<Predecessor table utility functions@>=

static inline enum lsmsb_opcode lsmsb_op_opcode_get(uint32_t op)
{
	return (enum lsmsb_opcode) (op >> 24);
}

static inline char lsmsb_opcode_falls_through(enum lsmsb_opcode opcode)
{
	return opcode != LSMSB_OPCODE_RET &&
	       opcode != LSMSB_OPCODE_JMP;
}

static inline unsigned lsmsb_opcode_is_jump(enum lsmsb_opcode opcode)
{
	return opcode == LSMSB_OPCODE_JMP || opcode == LSMSB_OPCODE_JC;
}

static inline unsigned lsmsb_op_jump_length(uint32_t op)
{
	const unsigned opcode = op >> 24;
	if (opcode == LSMSB_OPCODE_JMP || opcode == LSMSB_OPCODE_JC)
		return op & 0xff;
	return 0;
}

static inline unsigned lsmsb_op_reg1_get(uint32_t op)
{
	return (op >> 20) & 0xf;
}

static inline unsigned lsmsb_op_reg2_get(uint32_t op)
{
	return (op >> 16) & 0xf;
}

static inline unsigned lsmsb_op_reg3_get(uint32_t op)
{
	return (op >> 12) & 0xf;
}

static inline unsigned lsmsb_op_spill1_get(uint32_t op)
{
	return (op >> 16) & 0xff;
}

static inline unsigned lsmsb_op_spill2_get(uint32_t op)
{
	return (op >> 12) & 0xff;
}

static inline unsigned lsmsb_op_constant1_get(uint32_t op)
{
	return op & 0xff;
}

static inline unsigned lsmsb_op_imm_get(uint32_t op)
{
	return op & 0xfffff;
}

static inline void lsmsb_value_u32_set(struct lsmsb_value *value, unsigned v)
{
	value->data = NULL;
	value->value = v;
}

@/ Filter contexts

<p>The context of a filter (the semantics and types of the registers on entry)
are specified implicitly in the code for running each different type of filter.
In order to perform typechecking we need to duplicate that information
, or at least the types, here.</p>

@<Filter contexts@>=

struct filter_context {
  const char *filter_name;
  const char *type_string;
};

const struct filter_context filter_contexts[] = {
  {"dentry-open", "BI"}, // LSMSB_FILTER_CODE_DENTRY_OPEN
  {NULL, NULL}
};

@/ Getting an initial type vector for a filter

<p>Once we have <tt>filter_contexts</tt>, we can define a function to build
an initial type vector for a filter given the type string.</p>

@<type_vector_for_filter|Getting a type vector for a filter@>=

static uint8_t *type_vector_for_filter(const struct lsmsb_filter *filter,
				       const char *context_string)
{
	uint8_t *tv = kmalloc(lsmsb_filter_tva_width(filter), GFP_KERNEL);
	unsigned i;

	if (!tv)
		return NULL;
	memset(tv, 0, lsmsb_filter_tva_width(filter));
	
	for (i = 0; ; ++i) {
		switch (context_string[i]) {
		case 0:
			return tv;
		case 'B':
			lsmsb_type_vector_reg_set(tv, i, LSMSB_TYPE_BYTESTRING);
			break;
		case 'I':
			lsmsb_type_vector_reg_set(tv, i, LSMSB_TYPE_U32);
			break;
		default:
			BUG_ON(1);
			return tv;
		}
	}
}

@/ Installing sandboxes.

<p>
  A sandbox is installed from userspace by writing a compact representation of
  a set of filters to the kernel. Currently, the userspace process does this by
  writing to <tt>/proc/self/sandbox</tt>, although that could change in future
  versions.
</p>

@<Installing sandboxes@>=

@<Installing a constant@>

@<Handling sandbox lifetimes@>

@<Installing a filter@>

@<Installing a sandbox@>

@/ External structures

<p>
  Several structures are used in the data which is provided to the kernel. These
  structures thus become part of the kernel ABI. They are named with a <tt>_wire</tt>
  suffix to mark them as such.
</p>

@<External structures@>=

struct lsmsb_filter_wire {
	uint32_t filter_code;
	uint32_t num_operations;
	uint32_t num_spill_slots;
	uint32_t num_constants;
};

struct lsmsb_constant_wire {
	uint8_t type;  // 0 for integer, 1 for bytestring
	uint32_t value;
	/* In the case of a bytestring, the bytes follow and |value| is the length */
};

@/** Installing the sandbox

<p>
  The filters are prefixed by a <tt>uint32_t</tt> which contains the number of
  filters in this sandbox. As with most kernel APIs, the values are in
  native-endian.
</p>

<p>
  Then we read each filter in turn and insert it into the correct place in the
  sandbox. Once we have a complete sandbox, we can push it onto the stack of
  active sandboxes for the current process.
</p>

@<Installing a sandbox@>=

#define LSMSB_MAX_SANDBOXES_PER_PROCESS 16

int lsmsb_sandbox_install(struct task_struct *task,
			  const char __user *buf,
			  size_t len)
{
	uint32_t num_filters;
	struct lsmsb_sandbox *sandbox, *current_sandbox;
	struct cred *new_creds;
	unsigned i;
	int return_code;

	@<Check for limits on the number of sandboxes@>

	if (copy_from_user(&num_filters, buf, sizeof(num_filters)))
		return -EFAULT;
	buf += sizeof(num_filters);
	if (num_filters > 1 /* FIXME */)
		return -EINVAL;

	sandbox = kmalloc(sizeof(struct lsmsb_sandbox), GFP_KERNEL);
	if (!sandbox)
		return -ENOMEM;
	memset(sandbox, 0, sizeof(struct lsmsb_sandbox));

	for (i = 0; i < num_filters; ++i) {
		return_code = lsmsb_filter_install(sandbox, &buf);
		if (return_code)
			goto error;
	}

	@<Push a new sandbox onto the current process@>

	return 0;

error:
	lsmsb_sandbox_free(sandbox);
	kfree(sandbox);

	return return_code;
}

@/ Pushing a new sandbox

<p>
  The sandboxes are conceptually in a stack. The top of the stack is pointed by
  by the <tt>struct task_struct</tt> of a given process. Thus, pushing a new
  sandbox on the top of the stack involves an RCU update of the current
  <tt>struct task_struct</tt>.
</p>

@<Push a new sandbox onto the current process@>=
	atomic_set(&sandbox->refcount, 1);

	new_creds = prepare_creds();
	current_sandbox = new_creds->security;
	if (current_sandbox) {
		atomic_inc(&current_sandbox->refcount);
		sandbox->parent = current_sandbox;
	}
	new_creds->security = sandbox;
	commit_creds(new_creds);

@/ Limiting the number of sandboxes

<p>In order to stop userspace processes from consuming kernel memory
unboundedly, we limit the number of sandboxes which can be active for any given
process.</p>

@<Check for limits on the number of sandboxes@>=
	for (i = 0, sandbox = task->cred->security; sandbox; ++i)
		sandbox = sandbox->parent;
	if (i > LSMSB_MAX_SANDBOXES_PER_PROCESS)
		return -ENOSPC;

@/ Installing a filter

<p>
  Installing a filter involves copying the filter header from userspace, followed
  by the operation stream and any constants. At this point a number of limits are
  imposed on the sizes of the various structures for sanity's sake and also to
  avoid having to worry about integer overflows in other parts of the code.
</p>

<p>
  At this point we also learn the <tt>filter_code</tt>, which identifies the hook that
  this this filter processes. Once we know the filter code, we can typecheck the
  filter.
</p>

@<Installing a filter@>=

static int lsmsb_filter_install(struct lsmsb_sandbox *sandbox,
				const char __user **buf)
{
	struct lsmsb_filter_wire filter_wire;
	struct lsmsb_filter *filter;
	unsigned i;
	int return_code = -ENOMEM;
	uint8_t *type_vector;

	if (copy_from_user(&filter_wire, *buf, sizeof(filter_wire)))
		return -EFAULT;

	if (filter_wire.num_operations > LSMSB_FILTER_OPS_MAX ||
	    filter_wire.num_spill_slots > LSMSB_SPILL_SLOTS_MAX ||
	    filter_wire.num_constants > LSMSB_CONSTANTS_MAX)
		return -EOVERFLOW;
	if (filter_wire.filter_code >= LSMSB_FILTER_CODE_MAX)
		return -EINVAL;

	*buf += sizeof(struct lsmsb_filter_wire);

	filter = kmalloc(sizeof(struct lsmsb_filter) +
			 filter_wire.num_constants * sizeof(struct lsmsb_value),
			 GFP_KERNEL);
	if (!filter)
		return -ENOMEM;
	filter->num_operations = filter_wire.num_operations;
	filter->num_spill_slots = filter_wire.num_spill_slots;
	filter->num_constants = filter_wire.num_constants;
	for (i = 0; i < filter_wire.num_constants; ++i)
		filter->constants[i].data = NULL;

	filter->operations = kmalloc(filter->num_operations * sizeof(uint32_t),
				     GFP_KERNEL);
	if (!filter->operations)
		goto error;
	if (copy_from_user(filter->operations, *buf,
			   filter->num_operations * sizeof(uint32_t))) {
		return_code = -EFAULT;
		goto error;
	}
	*buf += filter->num_operations * sizeof(uint32_t);

	for (i = 0; i < filter_wire.num_constants; ++i) {
		return_code = lsmsb_constant_install(&filter->constants[i],
						     buf);
		if (return_code)
			goto error;
	}

	type_vector = type_vector_for_filter(
		filter, filter_contexts[filter_wire.filter_code].type_string);
	if (!type_vector) {
		return_code = -ENOMEM;
		goto error;
	}

	return_code = lsmsb_filter_typecheck(filter, type_vector);
	if (return_code)
		goto error;

	switch (filter_wire.filter_code) {
	case LSMSB_FILTER_CODE_DENTRY_OPEN:
		if (sandbox->dentry_open) {
			return_code = -EINVAL;
			goto error;
		}
		sandbox->dentry_open = filter;
		break;
	default:
		return_code = -EINVAL;
		goto error;
	}

	return 0;

error:
	lsmsb_filter_free(filter);
	return return_code;
}

@/ Installing a constant

<p>
  Each constant is described by a <tt>struct constant_wire</tt> and, optionally,
  followed by its data if it's a bytestring.
</p>

@<Installing a constant@>=

static int lsmsb_constant_install(struct lsmsb_value *value,
				  const char __user **buf)
{
	struct lsmsb_constant_wire constant_wire;

	if (copy_from_user(&constant_wire, *buf, sizeof(constant_wire)))
		return -EFAULT;
	if (constant_wire.type > 1)
		return -EINVAL;
	*buf += sizeof(constant_wire);

	value->value = constant_wire.value;
	if (constant_wire.type == 0)
		return 0;

	if (value->value > LSMSB_CONSTANT_LENGTH_MAX)
		return -EOVERFLOW;
	value->data = kmalloc(value->value, GFP_KERNEL);
	if (!value->data)
		return -ENOMEM;
	if (copy_from_user(value->data, *buf, value->value)) {
		kfree(value->data);
		return -EFAULT;
	}
	*buf += value->value;

	return 0;
}

@/** Interfacing with LSM

<p>
  LSM modules provide a structure of function pointers. Each function pointer
  corresponds to an LSM hook. For each hook that we wish to implement we need to
  provide a function which converts the hook's arguments to the form which the
  corresponding filter expects and runs the filter (if any) for each sandbox
  stacked on the current process.
</p>

@<LSM interface@>=

@<dentry_open hook@>

@<LSM operations structure@>

@/ Handling sandbox lifetimes

<p>
  We only have to provide a couple of functions to handle sandbox lifetimes. One
  to destroy sandboxes and another to duplicate them. (The sandboxes are
  reference countered, so &lsquo;duplicating&rsquo; is very cheap.)
</p>

@<Handling sandbox lifetimes@>=
static void lsmsb_filter_free(struct lsmsb_filter *filter)
{
	unsigned i;

	if (!filter)
		return;
	for (i = 0; i < filter->num_constants; ++i) {
		if (filter->constants[i].data)
			kfree(filter->constants[i].data);
	}
	if (filter->operations)
		kfree(filter->operations);
	kfree(filter);
}

static void lsmsb_sandbox_free(struct lsmsb_sandbox *sandbox)
{
	lsmsb_filter_free(sandbox->dentry_open);
	kfree(sandbox);
}

@<Dealing with cred structures@>

@/ <tt>cred</tt> structures

<p>A <tt>struct cred</tt> contains the authority of a process; it's various
UIDs and GIDs and an opaque pointer to the LSM data for a process. In our case,
that points to the sandbox that is at the top of the stack for the process.</p>

<p>We need a couple of functions to deal with them. The first comes into play
when duplicating a <tt>cred</tt> structure for a new process. The new process
initially gets the same sandbox stack as the parent so we just copy the pointer
and increment the reference count.</p>

<p>The second deals with freeing a <tt>cred</tt> structure. When freeing a
sandbox we have to keep in mind that the parent pointer is reference counted.
Thus, when we delete a sandbox that might cause it's parent to be deleted and
so on.</p>

@<Dealing with cred structures|Dealing with <tt>cred</tt> structures@>=
static int lsmsb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct lsmsb_sandbox *sandbox = old->security;
	new->security = sandbox;
	if (sandbox)
		atomic_inc(&sandbox->refcount);
	return 0;
}

static void lsmsb_cred_free(struct cred *cred)
{
	struct lsmsb_sandbox *sandbox = cred->security;
	struct lsmsb_sandbox *garbage;

	while (sandbox) {
		if (!atomic_dec_and_test(&sandbox->refcount))
			return;

		// The refcount hit 0
		garbage = sandbox;
		sandbox = sandbox->parent;
		lsmsb_sandbox_free(garbage);
	}
}

@/ The <tt>dentry_open</tt> hook

<p>We now come the list of hooks. These functions are LSM hook functions which
convert their arguments into a context for a filter and evaluate the stack of
sandboxes.</p>

<p><tt>dentry_open</tt> is called when a process opens a file. This function is
currently incomplete as it doesn't deal with files which cannot be named in the
current context (for example, the file is outside the current root for the
process). Nor does it currently deal differences between the view of the
filesystem that was active when the sandbox was installed vs the current view
of the filesystem.</p>

@<dentry_open hook@>=
static int lsmsb_dentry_open(struct file *f, const struct cred *cred)
{
	const struct lsmsb_sandbox *sandbox;
	char buffer[512];
	struct lsmsb_value registers[2];

	struct path root;
	struct path ns_root = { };
	struct path tmp;
	char *sp;

	if (!cred->security)
		return 0;
	sandbox = cred->security;

	while (sandbox) {
		if (sandbox->dentry_open)
			break;
		sandbox = sandbox->parent;
	}

	if (!sandbox)
		return 0;
	
	/* Taken from d_namespace_path(). */
	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);
	spin_lock(&vfsmount_lock);
	if (root.mnt && root.mnt->mnt_ns)
		ns_root.mnt = mntget(root.mnt->mnt_ns->root);
	if (ns_root.mnt)
		ns_root.dentry = dget(ns_root.mnt->mnt_root);
	spin_unlock(&vfsmount_lock);
	spin_lock(&dcache_lock);
	tmp = ns_root;
	sp = __d_path(&f->f_path, &tmp, buffer, sizeof(buffer));
	spin_unlock(&dcache_lock);
	path_put(&root);
	path_put(&ns_root);
	
	registers[0].data = sp;
	registers[0].value = strlen(sp);
	registers[1].data = NULL;
	registers[1].value = f->f_flags;

	while (sandbox) {
		if (sandbox->dentry_open) {
			if (!lsmsb_filter_run(sandbox->dentry_open,
					      registers, 2)) {
				return -EPERM;
			}
		}

		sandbox = sandbox->parent;
	}

	return 0;
}

@/

@<LSM operations structure@>=
struct security_operations lsmsb_ops = {
	.name   	= "lsmsb",
	.dentry_open    = lsmsb_dentry_open,
	.cred_prepare   = lsmsb_cred_prepare,
	.cred_free      = lsmsb_cred_free,
};


@/ Initialising the module

<p>
  LSM modules, despite the name, can no longer actually be loadable modules. They
  are initialised during the boot sequence by the security code so that they
  can label kernel objects early on.
</p>

<p>
  The security code only allows a single LSM module to register. Either this is
  the first module that tries to register, or the module named on the command
  line.
</p>

@<Module initialisation@>=
static __init int lsmsb_init(void)
{
	if (!security_module_enable(&lsmsb_ops))
		return 0;

	if (register_security(&lsmsb_ops))
		panic("lsmsb: Unable to register with kernel.\n");

	return 0;
}

security_initcall(lsmsb_init);

@{file lsmsb.c
#include <asm/atomic.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>

#include "lsmsb_external.h"

@<Value structure@>

@<Filter structure@>

@<Sandbox structure@>

@<List of operations@>

@<Filter codes@>

@<Typechecking@>

@<Evaluating filters@>

@<Installing sandboxes@>

@<LSM interface@>

@<Module initialisation@>

@{file lsmsb_external.h
@<External structures@>

@/* The assembler

<p>Obviously humans are going to need some assistance when building these
filter structures to load into the kernel. Preferably, a high level language
would allow programmers to precisely specify their desired level of access.
For now at least, we only provide a low level, assembly like language
for this purpose.</p>

<p>The following code defines a sandbox with a single filter for
<tt>dentry-open</tt>. If you recall, the context of <tt>dentry-open</tt>
specifies that the <tt>mode</tt> argument to <tt>open</tt> is provided in
register one. The following code tests the least significant bit of this
argument (which requests write access) and fails if it's set.</p>

@<ex1|LSMSB example code@>=
filter dentry-open {
  ldi r2,1;
  and r2,r1,r2;
  jc r2,#fail;
  ldi r0,1;
  ret r0;
#fail:
  ldi r0,0;
  ret r0;
}

@/ A more complex example

<p>Here we have a more complex example which involves bytestrings and
constants. As you can see, we define a bytestring constant named
<tt>etc-prefix</tt> which we can use as an argument to <tt>ldc</tt>.</p>

<p>Once loaded, we test the bytestring in register zero (which, according to
the context for <tt>dentry-open</tt>, is the full path to the file to be
opened) and test that <tt>/etc/</tt> is a prefix of the path.</p>

@<ex2|LSMSB example code@>=

filter dentry-open {
  constants {
    var etc-prefix bytestring = "/etc/";
  }

  ldc r2,etc-prefix;
  isprefixof r2,r2,r0;
  jc r2,#fail;
  ldi r0,1;
  ret r0;
#fail:
  ldi r0,0;
  ret r0;
}

@{file example-sandbox1.sb
@<ex1@>

@{file example-sandbox2.sb
@<ex2@>

@/ The filter structure

While parsing filters, we build up a structure called a <tt>Filter</tt> (we've
switched to C++ for this code).

@<lsmsb-as-filter|Filter structure@>=
struct Filter {
  Filter()
      : spill_slots(0),
        type_string(NULL),
        filter_code(LSMSB_FILTER_CODE_MAX) {
  }

  @<lsmsb-as-filter-typecheck@>
  @<lsmsb-as-filter-write@>

  std::string name;  // the name of the filter (i.e. "dentry-open")
  std::vector<Constant*> constants;
  unsigned spill_slots;
  std::vector<uint32_t> ops;
  const char *type_string;  // the types of this filter's context
  unsigned filter_code;  // the enum value of the filter
};

@/ The constant structure

<p>Constants in this language have a name and a type. We implement this as a base
class which holds the name with subclasses for each of the types.</p>

<p>The <tt>Write</tt> member serialises the constant to standard out in the
external format which the kernel expects.</p>

@<lsmsb-as-constant|Constant classes@>=
struct Constant {
  explicit Constant(const std::string &n)
      : name(n) {
  }

  enum Type {
    TYPE_U32,
    TYPE_BYTESTRING,
  };

  const std::string name;

  virtual Type type() const = 0;
  virtual bool Write() const = 0;
};

struct ByteString : public Constant {
  ByteString(const std::string &name, const std::string &ivalue)
      : Constant(name),
        value(ivalue) {
  }

  Type type() const {
    return TYPE_BYTESTRING;
  }

  bool Write() const {
    struct lsmsb_constant_wire wire;

    wire.type = 1;
    wire.value = value.size();

    if (!writea(1, &wire, sizeof(wire)) ||
        !writea(1, value.data(), value.size())) {
      return false;
    }

    return true;
  }

  const std::string value;
};

struct U32 : public Constant {
  U32(const std::string &name, uint32_t v)
      : Constant(name),
        value(v) {
  }

  Type type() const {
    return TYPE_BYTESTRING;
  }

  bool Write() const {
    struct lsmsb_constant_wire wire;

    wire.type = 0;
    wire.value = value;

    if (!writea(1, &wire, sizeof(wire)))
      return false;

    return true;
  }

  const uint32_t value;
};

@/** Parsing

<p>The parser is written using <a
href="http://www.complang.org/ragel/">Ragel</a> which generates code for a
state-machine parser from a description. Readers are directed to the Ragel
documentation to fully understand the following.</p>

<p>The parser is non-recursive and uses a single <tt>int</tt> value for its
current state. Several magic variables are used in the snippets of code
embedded in the parser:</p>

<table>
  <tr><td><tt>start</tt></td> <td>A pointer, into the input, to the start of the current word/string etc.</td></tr>
  <tr><td><tt>fpc</tt></td> <td>A pointer, into the input, to the byte which has just been parsed.</td></tr>
  <tr><td><tt>current_filter</tt></td> <td>A pointer to a <tt>Filter</tt> structure.</td></tr>
  <tr><td><tt>line_no</tt></td> <td>The current line number.</td></tr>
  <tr><td><tt>op</tt></td> <td>The current operation (a <tt>uint32_t</tt>).</td></tr>
</table>

<p>The first chunk of the parser defines an action (<tt>next_line</tt>) which
increments the current line counter, a parser (<tt>ws</tt>) to skip
whitespace and another action (<tt>start</tt>) to set the global <tt>start</tt>
variable.</p>

@<parser-1|First chunk of Ragel code@>=
  action next_line {
    line_no++;
  }

  ws = (' ' | '\t' | ('\n' %next_line) | "//" . (any - '\n') . ('\n' %next_line) | "/*" . any :>> "*/")*;

  action start {
    start = fpc;
  }

@/ Parsing a filter

@<parser-filter|Parsing a filter@>=
  filter = "filter" . ws . (token >start %filter_new) . ws . "{" . ws . constants? . spillslots? . inst* . ("}" @filter_push) . ws;

@/ Starting to parse a new filter

<p>In the Ragel chunk above, a token is parsed for the filter name and, at the
end of the token, the <tt>filter_new</tt> action is called. This sets the
global <tt>current_filter</tt> variable to a new filter and looks up the filter
name in the list of supported filters</p>

<p>When a filter is complete, it's pushed onto a list of filters.</p>

@<filter_new|Starting to parse a new filter@>=
  action filter_new {
    current_filter = new Filter;
    current_filter->name = std::string(start, fpc - start);

    for (unsigned i = 0; ; ++i) {
      if (filter_contexts[i].filter_name == NULL) {
        fprintf(stderr, "Error line %u: Unknown filter name '%s'\n", line_no, current_filter->name.c_str());
        abort();
      }

      if (filter_contexts[i].filter_name == current_filter->name) {
        current_filter->filter_code = i;
        current_filter->type_string = filter_contexts[i].type_string;
        break;
      }
    }
  }

  action filter_push {
    filters.push_back(current_filter);
    current_filter = NULL;
    jmp_targets.clear();
  }

@/ Parsing constants

@<Parsing constants@>=
  action constant_new {
    current_const_name = std::string(start, fpc - start);
  }

  action constant_bytestring_hex {
    current_filter->constants.push_back(new ByteString(current_const_name, hex_parse(std::string(start, fpc - start))));
  }

  action constant_bytestring_string {
    current_filter->constants.push_back(new ByteString(current_const_name, std::string(start, fpc - start)));
  }

  action constant_u32 {
    current_filter->constants.push_back(new U32(current_const_name, u32_parse(std::string(start, fpc - start))));
  }

  token = [a-zA-Z\-_][0-9a-zA-Z\-_]*;
  u32 = "0x"? . digit+;
  constant_u32 = "u32" . ws . "=" . ws . (u32 >start %constant_u32) . ws;
  bytestring_literal_hex = "x\"" . ([0-9a-fA-F]* >start %constant_bytestring_hex) . "\"" . ws;
  bytestring_literal_string = "\"" . ((any - '"')* >start %constant_bytestring_string) . "\"" . ws;
  bytestring_literal = bytestring_literal_hex | bytestring_literal_string;
  constant_bytestring = "bytestring" . ws . "=" . ws . bytestring_literal;
  constant_type_and_value = constant_u32 | constant_bytestring;
  constant = "var" . ws . (token >start %constant_new) . ws . constant_type_and_value . ws . ";" . ws;
  constants = "constants" . ws . "{" . ws . constant* . "}" . ws;

@/ Helper functions

@<Constant parsing helper functions@>=

static uint8_t
from_hex_char(char h) {
  if (h >= '0' && h <= '9')
    return h - '0';
  if (h >= 'a' && h <= 'f')
    return (h - 'a') + 10;
  return (h - 'A') + 10;
}

static std::string
hex_parse(const std::string &in) {
  uint8_t *bytes = (uint8_t *) malloc(in.size() / 2);

  for (size_t i = 0; i < in.size() / 2; ++i) {
    bytes[i] = (from_hex_char(in[i*2]) << 4) |
                from_hex_char(in[i*2 + 1]);
  }

  std::string ret((const char *) bytes, in.size() / 2);
  free(bytes);
  return ret;
}

static uint32_t
u32_parse(const std::string &in) {
  return strtoul(in.c_str(), NULL, 0);
}

@/ Parsing the spill slots declaration

@<Parsing the spill slots declaration@>=
  action set_spill_slots {
    current_filter->spill_slots = u32_parse(std::string(start, fpc - start));
  }

  spillslots = "spill-slots" . ws . (u32 >start %set_spill_slots) . ws . ";" . ws;

@/ Parsing instructions

<p>After the constants and spill-slots declarations, each line is an
'instruction'. I put the word in quotes because a jump target is included as an
instruction according to the parser, but it doesn't actually emit an operation
in the filter. Since all our jumps are forwards, jump resolution is simple and
we do everything in a single pass.</p>

@<Parsing instructions@>=
  inst = jump_target | and | ldc | ldi | jc | jmp | isprefixof | ret;

@/ Parsing simple instructions

<p>First we'll consider how to parse the easy instructions which don't
reference any other structures.</p>

@<Parsing simple instructions@>=

@<set_reg-helpers@>
@<push_op@>
@<simple-insts@>

@/ Helper actions

<p>We build up the current operation (in the global <tt>op</tt>) as we parse,
so we start with a bunch of helper actions for setting various parts of
<tt>op</tt>.</p>

@<set_reg-helpers|Helper actions@>=
  reg = "r" digit+;

  action set_reg1 {
    op |= reg_parse(std::string(start, fpc - start)) << 20;
  }
  action set_reg2 {
    op |= reg_parse(std::string(start, fpc - start)) << 16;
  }
  action set_reg3 {
    op |= reg_parse(std::string(start, fpc - start)) << 12;
  }
  action set_imm {
    op |= imm_check(u32_parse(std::string(start, fpc - start)));
  }

@/ Helper functions

<p>Those helper actions called several helper functions which we'll expand on
now:</p>

@<set_reg-functions|Helper functions@>=

static uint32_t
imm_check(uint32_t v) {
  if ((v & 0xfffff) != v) {
    fprintf(stderr, "Immediate value too large: %d\n", v);
    abort();
  }

  return v;
}

static uint32_t
reg_parse(const std::string &r) {
  return strtoul(r.c_str() + 1, NULL, 10);
}

@/ Pushing new operations

<p>Every time we complete an operation, we need to add it to the current
filter:</p>

@<push_op|Pushing operations@>=
  action push_op {
    current_filter->ops.push_back(op);
    op = 0;
  }

@/ Parsing the simple operations

@<simple-insts|Parsing the simple operations@>=

  action opcode_ldi {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_LDI) << 24;
  }
  ldi = ("ldi" %opcode_ldi) . ws . (reg >start %set_reg1) . "," . ws . (u32 >start %set_imm) . ws . (";" %push_op) . ws;

  action opcode_ret {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_RET) << 24;
  }
  ret = ("ret" %opcode_ret) . ws . (reg >start %set_reg1) . ws . (";" %push_op) . ws;

  action opcode_and {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_AND) << 24;
  }
  and = ("and" %opcode_and) . ws .
        (reg >start %set_reg1) . ws . "," . ws .
        (reg >start %set_reg2) . ws . "," . ws .
        (reg >start %set_reg3) . ws .
        (";" %push_op) . ws;

  action opcode_isprefixof {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_ISPREFIXOF) << 24;
  }
  isprefixof = ("isprefixof" %opcode_isprefixof) . ws .
               (reg >start %set_reg1) . ws . "," . ws .
               (reg >start %set_reg2) . ws . "," . ws .
               (reg >start %set_reg3) . ws .
               (";" %push_op) . ws;

@/ Parsing <tt>ldc</tt>

<p>The <tt>ldc</tt> instruction is a little more complicated since we have to
translate the constant name, given in the instruction, into an index into the
constant table.</p>

<p>We simply use the order which the constants were defined as the index and
walk the vector till we find the correct index.</p>

@<parse-ldc|Parsing <tt>ldc</tt>@>=
  action set_const {
    const std::string constant_name(start, fpc - start);
    unsigned i;

    for (i = 0; i < current_filter->constants.size(); ++i) {
      if (current_filter->constants[i]->name == constant_name) {
        op |= i;
        break;
      }
    }

    if (i == current_filter->constants.size()) {
      fprintf(stderr, "Error line %u: Unknown constant: %s\n", line_no, constant_name.c_str());
      abort();
    }
  }

  action opcode_ldc {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_LDC) << 24;
  }
  ldc = ("ldc" %opcode_ldc) . ws . (reg >start %set_reg1) . "," . ws . (token >start %set_const) . ws . (";" %push_op) . ws;

@/ Parsing jumps

<p>In the code which the kernel sees, all the jumps are expressed as an
unsigned number of operations to skip. However, people don't like writing code
like that, counting lines and all, so we let them specify jump targets as
strings and define them later.</p>

<p>So, uniquely for jump instructions, we don't actually know what the
exact operation is when we finish parsing the instruction: the offset is still
unknown. Thus we keep a map of named jump targets to a vector of offsets into
the operation list for jumps to that label.</p>

<p>When we parse a jump, we add an entry to the map for the current instruction
and when we parse a jump target, we lookup in the map and write the correct
offset for each instruction which jumps there.</p>

@<Parsing jumps@>=
  action jmp_mark {
    const std::string target = std::string(start, fpc - start);
    const std::map<std::string, std::vector<unsigned> >::iterator i =
      jmp_targets.find(target);

    if (i == jmp_targets.end()) {
      jmp_targets[target].push_back(current_filter->ops.size());
    } else {
      i->second.push_back(current_filter->ops.size());
    }
  }

  action opcode_jmp {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_JMP) << 24;
  }
  jmp = ("jmp" %opcode_jmp) . ws . '#' . (token >start %jmp_mark) . ws . (";" %push_op) . ws;

  action opcode_jc {
    op |= static_cast<uint32_t>(LSMSB_OPCODE_JC) << 24;
  }
  jc = ("jc" %opcode_jc) . ws . (reg >start %set_reg1) . ws . "," . ws . '#' . (token >start %jmp_mark) . ws . (";" %push_op) . ws;

  action jump_resolve {
    const std::string target = std::string(start, fpc - start);
    const std::map<std::string, std::vector<unsigned> >::iterator i =
      jmp_targets.find(target);

    if (i == jmp_targets.end()) {
      fprintf(stderr, "Error line %u: Jump target without any jumps (%s)\n", line_no, target.c_str());
      abort();
    }

    for (std::vector<unsigned>::const_iterator
         j = i->second.begin(); j != i->second.end(); ++j) {
      current_filter->ops[*j] |= current_filter->ops.size() - *j;
    }

    jmp_targets.erase(i);
  }
  jump_target = '#' . (token >start %jump_resolve) . ':' . ws;

@/ Parsing a whole file

<p>A file, as a whole, is just a list of filters:</p>

@<Parsing a file@>=
  as := ws . filter*;

@/ The <tt>main</tt> function

@<main@>=
int
main(int argc, char **argv) {
  @<main-openread@>

  @<parsing-globls@>

  %% write init;
  %% write exec;

  if (cs == as_error) {
    fprintf(stderr, "Error line %u: parse failure around: %s\n", line_no, p);
  }

  @<typecheck-filters@>

  @<serialise-filters@>

  return 0;
}

@/ Opening and reading the input

@<main-openread|Opening and reading the input@>=
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
    return 1;
  }

  const int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("Cannot open input file");
    return 1;
  }

  struct stat st;
  fstat(fd, &st);

  char *input = (char *) malloc(st.st_size);
  read(fd, input, st.st_size);
  close(fd);

@/ Parsing variables

<p>A detailed <a href="@@cite:parser-1@@">above</a>, during parsing a number of
globals are used. These happen to not actually be globals in the C sense. Since
the parsing code is expanded inline into this function, the 'globals' are
actually local variables to this function.</p>

@<parsing-globls@>=
  int cs;  // current parsing state
  uint32_t op = 0;  // current operation
  char *p = input;  // pointer to input
  const char *start = NULL;
  char *const pe = input + st.st_size;
  char *const eof = pe;
  unsigned line_no = 1;
  std::map<std::string, std::vector<unsigned> > jmp_targets;
  std::vector<Filter*> filters;
  Filter *current_filter = NULL;
  std::string current_const_name;

@/ Typechecking the filters

<p>Once we have parsed the filters we typecheck them since the kernel will
reject them anyway if they fail to typecheck. We simply call the
<tt>Typecheck</tt> member on each filter which we'll expand upon below.</p>

@<typecheck-filters@>=
  bool filter_failed = false;
  for (std::vector<Filter*>::const_iterator
       i = filters.begin(); i != filters.end(); ++i) {
    if ((*i)->Typecheck()) {
      fprintf(stderr, "Filter %s failed typecheck.\n", (*i)->name.c_str());
      filter_failed = true;
    }
  }

  if (filter_failed)
    return 1;

@/ Typechecking a filter

<p>We wouldn't want the typechecking to diverge between the kernel and
userspace, so we use the exact same code here as we do in the kernel.</p>

<p>We do so by filling out an <tt>lsmsb_filter</tt> structure and an array of
constants.</p>

@<lsmsb-as-filter-typecheck|bool Filter::Typecheck() const {...@>=
  bool Typecheck() const {
    const unsigned data_len = sizeof(struct lsmsb_filter) +
                              constants.size() * sizeof(struct lsmsb_value);
    uint8_t *filter_data = reinterpret_cast<uint8_t*>(malloc(data_len));
    memset(filter_data, 0, data_len);
    struct lsmsb_filter *filter = reinterpret_cast<lsmsb_filter*>(filter_data);

    filter->num_operations = ops.size();
    filter->num_spill_slots = spill_slots;
    filter->num_constants = constants.size();
    filter->operations = const_cast<uint32_t*>(&ops[0]);
    for (unsigned i = 0; i < constants.size(); ++i) {
      // It doesn't matter what value we use, as long as it isn't NULL so
      // |filter_data| is as good as any.
      filter->constants[i].data = constants[i]->type() == Constant::TYPE_BYTESTRING ?
                                  filter_data : NULL;
    }

    uint8_t* type_vector = type_vector_for_filter(filter, type_string);

    const bool ret = lsmsb_filter_typecheck(filter, type_vector);
    free(type_vector);
    free(filter);

    return ret;
  }

@/ Serialising the filters

<p>Once the filters have been typechecked, we write them out to stdout in the
format which the kernel expects to parse them in (see <a
href="@@cite:Installing a sandbox@@">the kernel code for installing a
sandbox</a>). This code follows the pattern of typechecking: all the actual
work is in an a <tt>Filter</tt> member function which we'll expand on
below.</p>

@<serialise-filters@>=
  const uint32_t num_filters = filters.size();
  writea(1, &num_filters, sizeof(num_filters));

  for (std::vector<Filter*>::const_iterator
       i = filters.begin(); i != filters.end(); ++i) {
    if (!(*i)->Write()) {
      fprintf(stderr, "Write failure writing to stdout\n");
      abort();
    }
  }

@/ Serialising a filter

<p>We serialise a filter by filling out the <a href="@@cite:External structures@@">external structures</a> which the kernel expects and writing to
<tt>stdout</tt>.</p>

@<lsmsb-as-filter-write|bool Filter::Write() const {...@>=
  bool Write() const {
    struct lsmsb_filter_wire wire;
    wire.filter_code = filter_code;
    wire.num_operations = ops.size();
    wire.num_spill_slots = spill_slots;
    wire.num_constants = constants.size();

    if (!writea(1, &wire, sizeof(wire)) ||
        !writea(1, &ops[0], sizeof(uint32_t) * ops.size())) {
      return false;
    }

    for (std::vector<Constant*>::const_iterator
         i = constants.begin(); i != constants.end(); ++i) {
      if (!(*i)->Write())
        return false;
    }

    return true;
  }

@/ The <tt>writea</tt> utility function

<p>This is a very thin wrapper around <tt>write</tt> which handles short
writes.</p>

@<writea|<tt>writea</tt>@>=
static bool writea(int fd, const void *in_data, size_t length)
{
  size_t done = 0;
  const uint8_t *data = reinterpret_cast<const uint8_t*>(in_data);

  while (done < length) {
    ssize_t result;

    do {
      result = write(fd, data + done, length - done);
    } while (result == -1 && errno == EINTR);

    if (result < 0)
      return false;
    done += result;
  }

  return true;
}

@/ Compatibility with kernel code

<p>Several of the functions which we are using in this code were written for
the kernel code and, as such, use kernel specific functions like
<tt>kmalloc</tt>. In order to have them run in a userspace context we provide
small shims for them.</p>

@<Kernel compatibility code@>=

#include <assert.h>
#include <stdlib.h>
#define GFP_KERNEL 0
#define BUG_ON(x) assert(!(x))

uint8_t* kmalloc(size_t size, int unused) {
  return (uint8_t*) malloc(size);
}
void kfree(void* heap) { free(heap); }

@{file lsmsb-as.rl
#include <string>
#include <vector>
#include <map>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

@<Kernel compatibility code@>

@<Value structure@>

@<Filter structure@>

@<List of operations@>

@<Filter codes@>

@<Typechecking@>

@<External structures@>

@<writea@>

@<Constant parsing helper functions@>

@<set_reg-functions@>

%%{
  machine as;

@<parser-1@>

@<filter_new@>

@<Parsing constants@>

@<Parsing the spill slots declaration@>

@<Parsing simple instructions@>

@<parse-ldc@>

@<Parsing jumps@>

@<Parsing instructions@>

@<parser-filter@>

@<Parsing a file@>

  write data;
}%%

@<lsmsb-as-constant@>
@<lsmsb-as-filter@>
@<main@>

@/* Using a sandbox

<p>Once a sandbox has been built, using it is very simple. One needs only to
write the sandbox to <tt>/proc/self/sandbox</tt>. We provide a very simple
binary which installs a given sandbox and runs a shell within it.</p>

<p>Note that, because sandboxes are composable, this can be done multiple
times.</p>

@<sb-install|Activate a sandbox@>=
  const int sandboxfd = open("/proc/self/sandbox", O_WRONLY);
  if (sandboxfd < 0) {
    perror("Opening /proc/self/sandbox");
    return 1;
  }

  if (write(sandboxfd, buffer, st.st_size) == -1) {
    perror("Installing sandbox");
    return 1;
  }

@{file lsmsb-install.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int
usage(const char *argv0) {
  fprintf(stderr, "Usage: %s <sandbox file>\n", argv0);
  return 1;
}

int
main(int argc, char **argv) {
  if (argc != 2)
    return usage(argv[0]);

  const int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("opening input");
    return 1;
  }

  struct stat st;
  fstat(fd, &st);

  uint8_t *buffer = malloc(st.st_size);
  read(fd, buffer, st.st_size);

  @<sb-install@>

  fprintf(stderr, "Sandbox installed\n");

  execl("/bin/bash", "/bin/bash", NULL);

  return 127;
}
