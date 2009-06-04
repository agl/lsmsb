<html>
  <head>
    <title>LSMSB</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <link href="style.css" rel="stylesheet" charset="utf-8">
  </head>

  <body>
    <h1>LSMSB: A Linux Sandboxing Scheme</h1>

<p>Adam Langley (<tt>agl@google.com</tt>)<br>
Version <tt>20090506</tt></p>

<p>This is LSMSB, a sandboxing scheme for Linux based on the ideas of the OS X
sandbox (which, in turn, was inspired by TrustedBSD and FreeBSD). We aim to
be:</p>

<ol>
<li>Available: The sandbox must be available to normal users. MAC systems
which are only configured by root are not the correct solution for this.</li>
<li>Flexible: <tt>seccomp</tt> is (currently) too rigid to really be useful. A
sandbox must be able to express the correct level of authority.</li>
<li>Reliable: The sandbox should not be open to races etc.</li>
<li>Deployable: One should be able to use a sandbox via a couple of call in
<tt>main</tt>(). If you have to implement an IPC system and pass file descriptors around
in order to achieve reliability (i.e. current pthread in the face of threads)
then that's a significant demerit.</li>
<li>Composable: If I choose to impose a sandbox on a process before <tt>exec</tt>()
then that process should still be able to impose another sandbox on itself. The
resulting authority should be the intersection of the two sandboxes.</li>
<li>Affordable: It should be reasonable to sandbox many processes. If the
sandbox has a high performance impact, then that's a problem. If the sandbox
requires a tracing process for every sandboxed process, then that's a
problem.</li>
</ol>

<p>LSMSB uses the Linux Security Modules hooks to intercept security decisions in
the kernel. The policies are implemented by tables of rules which are uploaded
from user-space. Each process has a stack of zero or more sandboxes. Each
sandbox may define a rule table for a given operation. An action must be
accepted by all the sandboxes in the stack for it to be permitted. Child
processes inherit the sandbox stack of their parents and are free to push extra
sandboxes onto their stack. By construction, this can only reduce their
authority.</p>

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

<p>Each rule in the table is a single 32-bit unsigned integer. Because of this, we
need another way to reference constant values as they generally don't fit
in 32-bits. Thus constants are kept in a side array, linked with each filter.
The rules in the table can reference them by index.</p>

<p>For working storage, the rules in the table have an array of 16 registers which
can either store a 32-bit unsigned integer or a byte-string (which is a normal
string, but may contain NUL charactors). If a table is exceedingly complex, it
may need more than 16-registers of storage to hold temporary values. For these
situations, we also allow the rule table to specifiy the number of spill slots
that it needs. Spill slots act just like registers except that they have to be
read and written explicitly.</p>

<p>From this, the structure for a filter is pretty obvious:</p>

@<Filter structure@>=
struct lsmsb_filter {
	unsigned num_operations;
	unsigned num_spill_slots;
	unsigned num_constants;
	uint32_t *operations;
	struct lsmsb_value constants[0];
};

@/ Filter values

<p>
  The contents of registers, spill slots and constants are all `values'. These
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
  numbers etc) encoded in the remaining 24-bits. The format is which is specific
  to each operation.
</p>

<p>
  The operations are numbered from zero by the following enum:
</p>

<table>
  <tr><th>Name</th><th>Explanation</th><th>Effect</th></tr>

  <tr><td><tt>MOV</tt></td> <td>Move</td> <td>reg<sub>1</sub> = reg<sub>2</sub></td></tr>
  <tr><td><tt>LDI</tt></td> <td>Load mmediate</td> <td>reg<sub>1</sub> = immediate value</td></tr>
  <tr><td><tt>LDC</tt></td> <td>Load constant</td> <td>reg<sub>1</sub> = constant value</td></tr>
  <tr><td><tt>RET</tt></td> <td>Return value in register</td> <td><i>terminates the filter</i></td></tr>
  <tr><td><tt>JMP</tt></td> <td>Jump</td> <td>Skips the next <i>n</i> rules</td></tr>
  <tr><td><tt>SPILL</tt></td> <td>Spill register</td> <td>spill<sub>1</sub> = reg<sub>1</sub></td></tr>
  <tr><td><tt>UNSPILL</tt></td> <td>Unspill register</td> <td>reg<sub>1</sub> = spill<sub>1</sub></td></tr>
  <tr><td><tt>JC</tt></td> <td>Jump conditionally</td> <td>If reg<sub>1</sub> &gt; 0 then skip the next <i>n</i> rules</td></tr>
  <tr><td><tt>EQ</tt></td> <td>Equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> == reg<sub>3</sub></td></tr>
  <tr><td><tt>GT</tt></td> <td>Greater than?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &gt; reg<sub>3</sub></td></tr>
  <tr><td><tt>LT</tt></td> <td>Less than?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &lt; reg<sub>3</sub></td></tr>
  <tr><td><tt>GTE</tt></td> <td>Greater than or equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &lt;= reg<sub>3</sub></td></tr>
  <tr><td><tt>LTE</tt></td> <td>Less than or equal?</td> <td>reg<sub>1</sub> = reg<sub>2</sub> &gt;= reg<sub>3</sub></td></tr>
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

@/ Availible filter types

<p>
  The type of a filter defines the filter will be evaluated and the arguments which
  are passed to the filter. Here are the currently defined filter types:
</p>

<table>
  <tr><th>Name</th> <th>Explanation</th> <th>Arguments</th></tr>

  <tr><td><tt>DENTRY_OPEN</tt></td> <td>File open</td> <td>Filename(<i>bs</i>) and mode(<i>i</i>)</td></tr>
</table>

@<Filter codes@>=
enum lsmsb_filter_code {
	LSMSB_FILTER_CODE_DENTRY_OPEN = 0,
	LSMSB_FILTER_CODE_MAX,  // not a real filter code
};

@/ Typechecking.

<p>
  The rule tables are simple enough that they can be validated such that we can
  know they they can never cause a run-time error. This is helpful as it means
  that we can pay the verification cost once (when loading the table) and omit
  run-time checks when evaluating.
</p>

@<Typechecking@>=

@<Predecessor tables@>

@<Type unification@>

@<Typecheck function@>

@/ Predecessor tables

<p>
  For each rule in the table there is a set of rules which can be the immediate
  predecessor of that rule. In the simple case, the rule preceeding will fall
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

@<Predecessor tables@>=

/* This is the magic NULL value in the predecessor table. This value must be
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
  find its one or two sucessor instructions and mark it as a predecessor for
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

@/ Utility functions

<P>
  We used a few utility functions in this code which we'll now flesh out.
</P>

@<Predecessor table utility functions@>=

static inline enum lsmsb_opcode lsmsb_op_opcode_get(uint32_t op)
{
	return op >> 24;
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

static inline unsigned lsmsb_op_jump_length(uint32_t op) {
	const unsigned opcode = op >> 24;
	if (opcode == LSMSB_OPCODE_JMP || opcode == LSMSB_OPCODE_JC)
		return op & 0xff;
	return 0;
}

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

@<Type unification@>=

enum lsmsb_type {
	LSMSB_TYPE_UNDEF = 0,
	LSMSB_TYPE_U32,
	LSMSB_TYPE_BYTESTRING,
	LSMSB_TYPE_CONFLICTING,
};

@<Type vector unification@>

@<Type vector updating@>

@<Type vector arrays@>

@<Filter contexts@>

@/ Unifing type vectors

<p>
  Given two type vectors (say, the type vectors from the two predecessors of a
  rule), we unify them by considering each element of each vector, pairwise.
  Then, for each pair, if they match then we output that value, otherwise, we
  record the value as conflicting.
</p>

<p>
  To implement this quickly, we try to operate on many elements concurrently.
  Most of the time a rule table will not use spill slots so the type vector will
  be 2 * 16 = 32 bits long and we can do them all in one go.
</p>

<p>
  To understand the code below, consider a single pair of 2-bit inputs. If we
  exclusive-or them, we'll end up with a 1 bit iff the inputs differed. If we
  could map 01, 10, and 11 to 11 and then OR with the original input, that would
  map equal inputs to themselves and differing inputs to
  <tt>LSMSB_TYPE_CONFLICTING</tt>.
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

static void lsmsb_type_vector_unify(uint8_t *a, const uint8_t *b, unsigned bytelen) {
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

	memset(tva, tva_width, 0);  /* set the first row to LSMSB_TYPE_UNDEF */
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
			@<Type vector array: handle overflowed row@>
		} else {
			@<Type vector array: handle normal row@>
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

@/ Unifing normal rows

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

@<Type vector array: handle normal row@>=
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

@/ Unifing overflow rows

<p>
  When the precedessor table is marked as overflowed, we have to find all the
  predecessors ourselves. We can do this by checking all previous operations for
  jumps to the current operation and checking the previous instruction for fall
  though. (Recall that we only have forward jumps.)
</p>

@<Type vector array: handle overflowed row@>=
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
	uint16_t *predecessor_table = kmalloc(
		filter->num_operations *
		LSMSB_PREDECESSOR_TABLE_WIDTH *
		sizeof(uint16_t), GFP_KERNEL);
	uint8_t *type_vector_array = kmalloc(filter->num_operations *
					     tva_width, GFP_KERNEL);
	int return_code = -EINVAL;
	
	if (!predecessor_table)
		return -ENOMEM;
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

@/ Filter contexts

<p>
  When typechecking a filter, it has a context implied in the code. For
  typechecking, we also need to mirror that context so that we can create the
  initial type vector.
</p>

@<Filter contexts@>=

static const char *filter_contexts[] = {
	"BI",  // DENTRY_OPEN
};

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

@<Installing a filter@>

@<Installing a sandbox@>

@/ External structures

<p>
  Several structures are used in the data which is provided to the kernel. These
  structures thus become part of the kernel ABI. They are named with a |_wire|
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

@/ Installing the sandbox

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

int lsmsb_sandbox_install(struct task_struct *task,
			  const char __user *buf,
			  size_t len)
{
	uint32_t num_filters;
	struct lsmsb_sandbox *sandbox, *current_sandbox;
	struct cred *new_creds;
	unsigned i;
	int return_code;

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
  by the <tt>struct task_struct</tt> of a given process. Thus, pushing a new sandbox on
  the top of the stack involves an RCU update of the current <tt>struct task_struct</tt>.
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

@/ Installing a filter

<p>
  Installing a filter involves copying the filter header from userspace, followed
  by the operation stream and any constants. At this point a number of limits are
  imposed on the sizes of the various structures for sanities sake and also to
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

	if (copy_from_user(&filter_wire, *buf, sizeof(filter_wire)))
		return -EFAULT;

	if (filter_wire.num_operations > LSMSB_FILTER_OPS_MAX ||
	    filter_wire.num_spill_slots > LSMSB_SPILL_SLOTS_MAX ||
	    filter_wire.num_constants > LSMSB_CONSTANTS_MAX ||
	    filter_wire.filter_code > LSMSB_FILTER_CODE_MAX) {
		return -EOVERFLOW;
	}

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
	for (i = 0; i < filter_wire.num_constants; ++i) {
		if (filter->constants[i].data)
			kfree(filter->constants[i].data);
	}
	if (filter->operations)
		kfree(filter->operations);
	kfree(filter);

	return return_code;
}

@/ Installing a constant

<p>
  Each constant is described by a |struct constant_wire| and, optionally,
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

@/ Interfacing with LSM

<p>
  LSM modules provide a structure of function pointers. Each function pointer
  corresponds to an LSM hook. For each hook that we wish to implement we need to
  provide a function which converts the hook's arguments to the form which the
  corresponding filter expects and runs the filter (if any) for each sandbox
  stacked on the current process.
</p>

@<LSM interface@>=

@<dentry_open hook@>

@<Handling sandbox lifetimes@>

@<LSM operations structure@>

@/ Handling sandbox lifetimes

<p>
  We only have to provide a couple of functions to handle sandbox lifetimes. One
  to destroy sandboxes and another to duplicate them. Since the sandboxes are
  refcounted, we never actually duplicate them.
</p>

@<Handling sandbox lifetimes@>=
static void lsmsb_filter_free(struct lsmsb_filter *filter) {
	if (!filter)
		return;
	kfree(filter->operations);
	kfree(filter);
}

static void lsmsb_sandbox_free(struct lsmsb_sandbox *sandbox) {
	lsmsb_filter_free(sandbox->dentry_open);
	kfree(sandbox);
}

static int lsmsb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp) {
	struct lsmsb_sandbox *sandbox = (struct lsmsb_sandbox *) old->security;
	new->security = sandbox;
	if (sandbox)
		atomic_inc(&sandbox->refcount);
	return 0;
}

@<Freeing a cred structure@>

@/ Freeing sandboxes

<p>
  When freeing a sandbox we have to keep in mind that the parent pointer is
  reference counted. Thus, when we delete a sandbox that might cause it's parent
  to be deleted and so on.
</p>

@<Freeing a cred structure@>=
static void lsmsb_cred_free(struct cred *cred) {
	struct lsmsb_sandbox *sandbox = (struct lsmsb_sandbox *) cred->security;
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

@<dentry_open hook@>=
static int lsmsb_dentry_open(struct file *f, const struct cred *cred)
{
	const struct lsmsb_sandbox *sandbox;
	char buffer[512];
	struct lsmsb_value constants[2];

	struct path root;
	struct path ns_root = { };
	struct path tmp;
	char *sp;

	if (!cred->security)
		return 0;
	sandbox = (struct lsmsb_sandbox *) cred->security;

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
	
	constants[0].data = sp;
	constants[0].value = strlen(sp);
	constants[1].data = NULL;
	constants[1].value = f->f_flags;

	while (sandbox) {
		if (sandbox->dentry_open) {
			if (!lsmsb_filter_run(sandbox->dentry_open,
					      constants, 2)) {
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


@/ Initilising the module

<p>
  LSM modules, despite the name, can no longer actually be loadable modules. They
  are initilisaed during the boot sequence by the security code so that they
  can label kernel objects early on.
</p>

<p>
  The security code only allows a single LSM module to register. Either this is
  the first module that tries to register, or the module named on the command
  line.
</p>

@<Module initilisation@>=
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

#include "lsmsb.h"
#include "lsmsb_external.h"

@<Installing sandboxes@>

@<LSM interface@>

@<Module initilisation@>

@{file lsmsb_filter.c
#include <linux/string.h>
#include <linux/slab.h>

#include "lsmsb.h"
#include "lsmsb_filter.h"
#include "lsmsb_type_vector.h"

@<Typechecking@>

@{file lsmsb.h

@<Filter structure@>

@<Value structure@>

@<List of operations@>

@<Filter codes@>

@{file lsmsb_filter.h
@<Predecessor table utility functions@>

@{file lsmsb_external.h
@<External structures@>
