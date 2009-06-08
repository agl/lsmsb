#include <asm/atomic.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/mnt_namespace.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>

#include "lsmsb_external.h"

struct lsmsb_value {
	uint8_t *data;
	uint32_t value;
};

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

struct lsmsb_sandbox {
        atomic_t refcount;
        struct lsmsb_sandbox *parent;
        struct lsmsb_filter *dentry_open;
        // TODO: add support for more actions
};

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

enum lsmsb_filter_code {
	LSMSB_FILTER_CODE_DENTRY_OPEN = 0,
	LSMSB_FILTER_CODE_MAX,  // not a real filter code
};

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

/* This is the magic unset value in the predecessor table. This value must be
 * all ones because we clear the table with a memset. */
#define LSMSB_PREDECESSOR_TABLE_INVAL 0xffff
/* This is a magic value in the predecessor table which marks an overflow. */
#define LSMSB_PREDECESSOR_TABLE_OVERFLOW (LSMSB_FILTER_OPS_MAX + 1)
/* This is the number of predecessors that we record, per row, before
 * overflowing */
#define LSMSB_PREDECESSOR_TABLE_WIDTH 2

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

static char lsmsb_predecessor_table_fill(uint16_t *ptable, const uint32_t *ops, unsigned num_ops)
{
	unsigned i;

	if (num_ops == 0)
		return 1;

	memset(ptable, 0xff, sizeof(uint16_t) * num_ops * LSMSB_PREDECESSOR_TABLE_WIDTH);

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
		} else {
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

struct filter_context {
  const char *filter_name;
  const char *type_string;
};

const struct filter_context filter_contexts[] = {
  {"dentry-open", "BI"}, // LSMSB_FILTER_CODE_DENTRY_OPEN
  {NULL, NULL}
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

	for (i = 0, sandbox = task->cred->security; sandbox; ++i)
		sandbox = sandbox->parent;
	if (i > LSMSB_MAX_SANDBOXES_PER_PROCESS)
		return -ENOSPC;

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

	atomic_set(&sandbox->refcount, 1);

	new_creds = prepare_creds();
	current_sandbox = new_creds->security;
	if (current_sandbox) {
		atomic_inc(&current_sandbox->refcount);
		sandbox->parent = current_sandbox;
	}
	new_creds->security = sandbox;
	commit_creds(new_creds);

	return 0;

error:
	lsmsb_sandbox_free(sandbox);
	kfree(sandbox);

	return return_code;
}

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

struct security_operations lsmsb_ops = {
	.name   	= "lsmsb",
	.dentry_open    = lsmsb_dentry_open,
	.cred_prepare   = lsmsb_cred_prepare,
	.cred_free      = lsmsb_cred_free,
};

static __init int lsmsb_init(void)
{
	if (!security_module_enable(&lsmsb_ops))
		return 0;

	if (register_security(&lsmsb_ops))
		panic("lsmsb: Unable to register with kernel.\n");

	return 0;
}

security_initcall(lsmsb_init);
