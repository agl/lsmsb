#line 1 "lsmsb-as.rl"
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

#include <assert.h>
#include <stdlib.h>
#define GFP_KERNEL 0
#define BUG_ON(x) assert(!(x))

uint8_t* kmalloc(size_t size, int unused) {
  return (uint8_t*) malloc(size);
}
void kfree(void* heap) { free(heap); }

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


#line 623 "lsmsb-as.cc"
static const char _as_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 5, 1, 6, 1, 
	7, 1, 8, 1, 9, 1, 10, 1, 
	11, 1, 12, 1, 13, 1, 14, 1, 
	15, 1, 16, 1, 17, 1, 18, 1, 
	19, 1, 20, 1, 21, 1, 22, 1, 
	23, 2, 0, 1, 2, 0, 3, 2, 
	1, 5, 2, 1, 6, 2, 13, 3, 
	2, 14, 1, 2, 15, 1, 2, 16, 
	1, 2, 17, 1, 2, 19, 1, 2, 
	22, 1
};

static const short _as_key_offsets[] = {
	0, 0, 2, 2, 3, 4, 5, 6, 
	7, 8, 9, 10, 11, 21, 31, 44, 
	49, 54, 56, 56, 57, 58, 59, 60, 
	73, 86, 92, 101, 112, 123, 125, 125, 
	126, 127, 128, 129, 130, 131, 136, 141, 
	146, 148, 148, 149, 150, 151, 152, 154, 
	161, 166, 171, 176, 181, 183, 183, 184, 
	185, 186, 187, 189, 196, 201, 206, 211, 
	216, 218, 218, 219, 220, 221, 222, 224, 
	231, 236, 241, 243, 243, 244, 245, 246, 
	247, 258, 259, 260, 261, 262, 263, 264, 
	265, 266, 267, 272, 274, 279, 284, 289, 
	291, 291, 292, 293, 294, 295, 297, 304, 
	309, 314, 319, 324, 330, 343, 345, 345, 
	346, 347, 348, 349, 351, 351, 352, 353, 
	354, 355, 356, 361, 362, 364, 369, 374, 
	379, 381, 381, 382, 383, 384, 385, 387, 
	390, 400, 410, 423, 425, 425, 426, 427, 
	428, 429, 434, 439, 444, 446, 446, 447, 
	448, 449, 450, 452, 455, 462, 469, 471, 
	471, 472, 473, 474, 475, 483, 490, 492, 
	493, 494, 499, 504, 509, 511, 511, 512, 
	513, 514, 515, 517, 524, 526, 526, 527, 
	528, 529, 530, 532, 532, 533, 534, 535, 
	536, 538, 538, 539, 540, 541, 542, 543, 
	544, 545, 546, 547, 548, 549, 550, 555, 
	560, 562, 562, 563, 564, 565, 566, 572, 
	578, 580, 580, 581, 582, 583, 584, 585, 
	586, 596, 606, 620, 626, 632, 634, 634, 
	635, 636, 637, 638, 639, 640, 641, 642, 
	643, 644, 645, 646, 647, 652, 657, 659, 
	659, 660, 661, 662, 663, 669, 675, 676, 
	677, 682, 687, 689, 689, 690, 691, 692, 
	693, 695, 695, 696, 697, 698, 699, 700, 
	707, 714, 715, 716, 721, 726, 728, 728, 
	729, 730, 731, 732, 739, 746, 748, 748, 
	749, 750, 751, 752, 760, 767, 769, 784, 
	799, 814, 829, 836, 843, 845, 845, 846, 
	847, 848, 849, 864, 879, 894, 909, 924, 
	939, 954, 969, 984, 991, 998, 1000, 1000, 
	1001, 1002, 1003, 1004, 1006, 1006, 1007, 1008, 
	1009, 1010, 1022, 1034, 1036, 1036, 1037, 1038, 
	1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 
	1047, 1048, 1049, 1050, 1057, 1064, 1066, 1066, 
	1067, 1068, 1069, 1070, 1078, 1083, 1088, 1090, 
	1090, 1091, 1092, 1093, 1094, 1101, 1103, 1105, 
	1105, 1106, 1107, 1108, 1109, 1114
};

static const char _as_trans_keys[] = {
	42, 47, 42, 47, 10, 10, 105, 108, 
	116, 101, 114, 9, 10, 32, 45, 47, 
	95, 65, 90, 97, 122, 9, 10, 32, 
	45, 47, 95, 65, 90, 97, 122, 9, 
	10, 32, 45, 47, 95, 123, 48, 57, 
	65, 90, 97, 122, 9, 10, 32, 47, 
	123, 9, 10, 32, 47, 123, 42, 47, 
	42, 47, 10, 10, 9, 10, 32, 35, 
	47, 97, 99, 105, 106, 108, 114, 115, 
	125, 9, 10, 32, 35, 47, 97, 99, 
	105, 106, 108, 114, 115, 125, 45, 95, 
	65, 90, 97, 122, 45, 58, 95, 48, 
	57, 65, 90, 97, 122, 9, 10, 32, 
	35, 47, 97, 105, 106, 108, 114, 125, 
	9, 10, 32, 35, 47, 97, 105, 106, 
	108, 114, 125, 42, 47, 42, 47, 10, 
	10, 110, 100, 9, 10, 32, 47, 114, 
	9, 10, 32, 47, 114, 9, 10, 32, 
	47, 114, 42, 47, 42, 47, 10, 10, 
	48, 57, 9, 10, 32, 44, 47, 48, 
	57, 9, 10, 32, 44, 47, 9, 10, 
	32, 44, 47, 9, 10, 32, 47, 114, 
	9, 10, 32, 47, 114, 42, 47, 42, 
	47, 10, 10, 48, 57, 9, 10, 32, 
	44, 47, 48, 57, 9, 10, 32, 44, 
	47, 9, 10, 32, 44, 47, 9, 10, 
	32, 47, 114, 9, 10, 32, 47, 114, 
	42, 47, 42, 47, 10, 10, 48, 57, 
	9, 10, 32, 47, 59, 48, 57, 9, 
	10, 32, 47, 59, 9, 10, 32, 47, 
	59, 42, 47, 42, 47, 10, 10, 9, 
	10, 32, 35, 47, 97, 105, 106, 108, 
	114, 125, 115, 112, 114, 101, 102, 105, 
	120, 111, 102, 9, 10, 32, 47, 114, 
	99, 109, 9, 10, 32, 47, 114, 9, 
	10, 32, 47, 114, 9, 10, 32, 47, 
	114, 42, 47, 42, 47, 10, 10, 48, 
	57, 9, 10, 32, 44, 47, 48, 57, 
	9, 10, 32, 44, 47, 9, 10, 32, 
	44, 47, 9, 10, 32, 35, 47, 9, 
	10, 32, 35, 47, 45, 95, 65, 90, 
	97, 122, 9, 10, 32, 45, 47, 59, 
	95, 48, 57, 65, 90, 97, 122, 42, 
	47, 42, 47, 10, 10, 42, 47, 42, 
	47, 10, 10, 112, 9, 10, 32, 35, 
	47, 100, 99, 105, 9, 10, 32, 47, 
	114, 9, 10, 32, 47, 114, 9, 10, 
	32, 47, 114, 42, 47, 42, 47, 10, 
	10, 48, 57, 44, 48, 57, 9, 10, 
	32, 45, 47, 95, 65, 90, 97, 122, 
	9, 10, 32, 45, 47, 95, 65, 90, 
	97, 122, 9, 10, 32, 45, 47, 59, 
	95, 48, 57, 65, 90, 97, 122, 42, 
	47, 42, 47, 10, 10, 9, 10, 32, 
	47, 114, 9, 10, 32, 47, 114, 9, 
	10, 32, 47, 114, 42, 47, 42, 47, 
	10, 10, 48, 57, 44, 48, 57, 9, 
	10, 32, 47, 48, 49, 57, 9, 10, 
	32, 47, 48, 49, 57, 42, 47, 42, 
	47, 10, 10, 9, 10, 32, 47, 59, 
	120, 48, 57, 9, 10, 32, 47, 59, 
	48, 57, 48, 57, 101, 116, 9, 10, 
	32, 47, 114, 9, 10, 32, 47, 114, 
	9, 10, 32, 47, 114, 42, 47, 42, 
	47, 10, 10, 48, 57, 9, 10, 32, 
	47, 59, 48, 57, 42, 47, 42, 47, 
	10, 10, 42, 47, 42, 47, 10, 10, 
	42, 47, 42, 47, 10, 10, 111, 110, 
	115, 116, 97, 110, 116, 115, 9, 10, 
	32, 47, 123, 9, 10, 32, 47, 123, 
	42, 47, 42, 47, 10, 10, 9, 10, 
	32, 47, 118, 125, 9, 10, 32, 47, 
	118, 125, 42, 47, 42, 47, 10, 10, 
	97, 114, 9, 10, 32, 45, 47, 95, 
	65, 90, 97, 122, 9, 10, 32, 45, 
	47, 95, 65, 90, 97, 122, 9, 10, 
	32, 45, 47, 95, 98, 117, 48, 57, 
	65, 90, 97, 122, 9, 10, 32, 47, 
	98, 117, 9, 10, 32, 47, 98, 117, 
	42, 47, 42, 47, 10, 10, 121, 116, 
	101, 115, 116, 114, 105, 110, 103, 9, 
	10, 32, 47, 61, 9, 10, 32, 47, 
	61, 42, 47, 42, 47, 10, 10, 9, 
	10, 32, 34, 47, 120, 9, 10, 32, 
	34, 47, 120, 34, 34, 9, 10, 32, 
	47, 59, 9, 10, 32, 47, 59, 42, 
	47, 42, 47, 10, 10, 42, 47, 42, 
	47, 10, 10, 34, 34, 48, 57, 65, 
	70, 97, 102, 34, 48, 57, 65, 70, 
	97, 102, 51, 50, 9, 10, 32, 47, 
	61, 9, 10, 32, 47, 61, 42, 47, 
	42, 47, 10, 10, 9, 10, 32, 47, 
	48, 49, 57, 9, 10, 32, 47, 48, 
	49, 57, 42, 47, 42, 47, 10, 10, 
	9, 10, 32, 47, 59, 120, 48, 57, 
	9, 10, 32, 47, 59, 48, 57, 48, 
	57, 9, 10, 32, 45, 47, 95, 98, 
	117, 121, 48, 57, 65, 90, 97, 122, 
	9, 10, 32, 45, 47, 51, 95, 98, 
	117, 48, 57, 65, 90, 97, 122, 9, 
	10, 32, 45, 47, 50, 95, 98, 117, 
	48, 57, 65, 90, 97, 122, 9, 10, 
	32, 45, 47, 61, 95, 98, 117, 48, 
	57, 65, 90, 97, 122, 9, 10, 32, 
	47, 61, 98, 117, 9, 10, 32, 47, 
	61, 98, 117, 42, 47, 42, 47, 10, 
	10, 9, 10, 32, 45, 47, 95, 98, 
	116, 117, 48, 57, 65, 90, 97, 122, 
	9, 10, 32, 45, 47, 95, 98, 101, 
	117, 48, 57, 65, 90, 97, 122, 9, 
	10, 32, 45, 47, 95, 98, 115, 117, 
	48, 57, 65, 90, 97, 122, 9, 10, 
	32, 45, 47, 95, 98, 116, 117, 48, 
	57, 65, 90, 97, 122, 9, 10, 32, 
	45, 47, 95, 98, 114, 117, 48, 57, 
	65, 90, 97, 122, 9, 10, 32, 45, 
	47, 95, 98, 105, 117, 48, 57, 65, 
	90, 97, 122, 9, 10, 32, 45, 47, 
	95, 98, 110, 117, 48, 57, 65, 90, 
	97, 122, 9, 10, 32, 45, 47, 95, 
	98, 103, 117, 48, 57, 65, 90, 97, 
	122, 9, 10, 32, 45, 47, 61, 95, 
	98, 117, 48, 57, 65, 90, 97, 122, 
	9, 10, 32, 47, 61, 98, 117, 9, 
	10, 32, 47, 61, 98, 117, 42, 47, 
	42, 47, 10, 10, 42, 47, 42, 47, 
	10, 10, 9, 10, 32, 35, 47, 97, 
	105, 106, 108, 114, 115, 125, 9, 10, 
	32, 35, 47, 97, 105, 106, 108, 114, 
	115, 125, 42, 47, 42, 47, 10, 10, 
	112, 105, 108, 108, 45, 115, 108, 111, 
	116, 115, 9, 10, 32, 47, 48, 49, 
	57, 9, 10, 32, 47, 48, 49, 57, 
	42, 47, 42, 47, 10, 10, 9, 10, 
	32, 47, 59, 120, 48, 57, 9, 10, 
	32, 47, 59, 9, 10, 32, 47, 59, 
	42, 47, 42, 47, 10, 10, 9, 10, 
	32, 47, 59, 48, 57, 48, 57, 42, 
	47, 42, 47, 10, 10, 9, 10, 32, 
	47, 102, 9, 10, 32, 47, 102, 0
};

static const char _as_single_lengths[] = {
	0, 2, 0, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 6, 6, 7, 5, 
	5, 2, 0, 1, 1, 1, 1, 13, 
	13, 2, 3, 11, 11, 2, 0, 1, 
	1, 1, 1, 1, 1, 5, 5, 5, 
	2, 0, 1, 1, 1, 1, 0, 5, 
	5, 5, 5, 5, 2, 0, 1, 1, 
	1, 1, 0, 5, 5, 5, 5, 5, 
	2, 0, 1, 1, 1, 1, 0, 5, 
	5, 5, 2, 0, 1, 1, 1, 1, 
	11, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 5, 2, 5, 5, 5, 2, 
	0, 1, 1, 1, 1, 0, 5, 5, 
	5, 5, 5, 2, 7, 2, 0, 1, 
	1, 1, 1, 2, 0, 1, 1, 1, 
	1, 1, 5, 1, 2, 5, 5, 5, 
	2, 0, 1, 1, 1, 1, 0, 1, 
	6, 6, 7, 2, 0, 1, 1, 1, 
	1, 5, 5, 5, 2, 0, 1, 1, 
	1, 1, 0, 1, 5, 5, 2, 0, 
	1, 1, 1, 1, 6, 5, 0, 1, 
	1, 5, 5, 5, 2, 0, 1, 1, 
	1, 1, 0, 5, 2, 0, 1, 1, 
	1, 1, 2, 0, 1, 1, 1, 1, 
	2, 0, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 5, 5, 
	2, 0, 1, 1, 1, 1, 6, 6, 
	2, 0, 1, 1, 1, 1, 1, 1, 
	6, 6, 8, 6, 6, 2, 0, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 5, 5, 2, 0, 
	1, 1, 1, 1, 6, 6, 1, 1, 
	5, 5, 2, 0, 1, 1, 1, 1, 
	2, 0, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 5, 5, 2, 0, 1, 
	1, 1, 1, 5, 5, 2, 0, 1, 
	1, 1, 1, 6, 5, 0, 9, 9, 
	9, 9, 7, 7, 2, 0, 1, 1, 
	1, 1, 9, 9, 9, 9, 9, 9, 
	9, 9, 9, 7, 7, 2, 0, 1, 
	1, 1, 1, 2, 0, 1, 1, 1, 
	1, 12, 12, 2, 0, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 5, 5, 2, 0, 1, 
	1, 1, 1, 6, 5, 5, 2, 0, 
	1, 1, 1, 1, 5, 0, 2, 0, 
	1, 1, 1, 1, 5, 5
};

static const char _as_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 2, 2, 3, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 2, 3, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 0, 
	0, 0, 0, 2, 3, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	2, 2, 3, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 1, 1, 0, 0, 
	0, 0, 0, 0, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	2, 2, 3, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 3, 
	3, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 0, 0, 0, 
	0, 0, 0, 1, 1, 1, 3, 3, 
	3, 3, 0, 0, 0, 0, 0, 0, 
	0, 0, 3, 3, 3, 3, 3, 3, 
	3, 3, 3, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 0, 0, 0, 
	0, 0, 0, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 1, 1, 0, 0, 
	0, 0, 0, 0, 0, 0
};

static const short _as_index_offsets[] = {
	0, 0, 3, 4, 6, 8, 10, 12, 
	14, 16, 18, 20, 22, 31, 40, 51, 
	57, 63, 66, 67, 69, 71, 73, 75, 
	89, 103, 108, 115, 127, 139, 142, 143, 
	145, 147, 149, 151, 153, 155, 161, 167, 
	173, 176, 177, 179, 181, 183, 185, 187, 
	194, 200, 206, 212, 218, 221, 222, 224, 
	226, 228, 230, 232, 239, 245, 251, 257, 
	263, 266, 267, 269, 271, 273, 275, 277, 
	284, 290, 296, 299, 300, 302, 304, 306, 
	308, 320, 322, 324, 326, 328, 330, 332, 
	334, 336, 338, 344, 347, 353, 359, 365, 
	368, 369, 371, 373, 375, 377, 379, 386, 
	392, 398, 404, 410, 415, 426, 429, 430, 
	432, 434, 436, 438, 441, 442, 444, 446, 
	448, 450, 452, 458, 460, 463, 469, 475, 
	481, 484, 485, 487, 489, 491, 493, 495, 
	498, 507, 516, 527, 530, 531, 533, 535, 
	537, 539, 545, 551, 557, 560, 561, 563, 
	565, 567, 569, 571, 574, 581, 588, 591, 
	592, 594, 596, 598, 600, 608, 615, 617, 
	619, 621, 627, 633, 639, 642, 643, 645, 
	647, 649, 651, 653, 660, 663, 664, 666, 
	668, 670, 672, 675, 676, 678, 680, 682, 
	684, 687, 688, 690, 692, 694, 696, 698, 
	700, 702, 704, 706, 708, 710, 712, 718, 
	724, 727, 728, 730, 732, 734, 736, 743, 
	750, 753, 754, 756, 758, 760, 762, 764, 
	766, 775, 784, 796, 803, 810, 813, 814, 
	816, 818, 820, 822, 824, 826, 828, 830, 
	832, 834, 836, 838, 840, 846, 852, 855, 
	856, 858, 860, 862, 864, 871, 878, 880, 
	882, 888, 894, 897, 898, 900, 902, 904, 
	906, 909, 910, 912, 914, 916, 918, 920, 
	925, 930, 932, 934, 940, 946, 949, 950, 
	952, 954, 956, 958, 965, 972, 975, 976, 
	978, 980, 982, 984, 992, 999, 1001, 1014, 
	1027, 1040, 1053, 1061, 1069, 1072, 1073, 1075, 
	1077, 1079, 1081, 1094, 1107, 1120, 1133, 1146, 
	1159, 1172, 1185, 1198, 1206, 1214, 1217, 1218, 
	1220, 1222, 1224, 1226, 1229, 1230, 1232, 1234, 
	1236, 1238, 1251, 1264, 1267, 1268, 1270, 1272, 
	1274, 1276, 1278, 1280, 1282, 1284, 1286, 1288, 
	1290, 1292, 1294, 1296, 1303, 1310, 1313, 1314, 
	1316, 1318, 1320, 1322, 1330, 1336, 1342, 1345, 
	1346, 1348, 1350, 1352, 1354, 1361, 1363, 1366, 
	1367, 1369, 1371, 1373, 1375, 1381
};

static const short _as_trans_targs[] = {
	2, 5, 0, 3, 4, 0, 372, 0, 
	0, 6, 373, 0, 8, 0, 9, 0, 
	10, 0, 11, 0, 12, 0, 12, 13, 
	12, 14, 366, 14, 14, 14, 0, 12, 
	13, 12, 14, 366, 14, 14, 14, 0, 
	15, 16, 15, 14, 17, 14, 23, 14, 
	14, 14, 0, 15, 16, 15, 17, 23, 
	0, 15, 16, 15, 17, 23, 0, 18, 
	21, 0, 19, 20, 0, 15, 0, 0, 
	22, 16, 0, 23, 24, 23, 25, 192, 
	35, 198, 81, 91, 123, 167, 337, 372, 
	0, 23, 24, 23, 25, 192, 35, 198, 
	81, 91, 123, 167, 337, 372, 0, 26, 
	26, 26, 26, 0, 26, 27, 26, 26, 
	26, 26, 0, 27, 28, 27, 25, 29, 
	35, 81, 91, 123, 167, 372, 0, 27, 
	28, 27, 25, 29, 35, 81, 91, 123, 
	167, 372, 0, 30, 33, 0, 31, 32, 
	0, 27, 0, 0, 34, 28, 0, 36, 
	0, 37, 0, 38, 39, 38, 40, 46, 
	0, 38, 39, 38, 40, 46, 0, 38, 
	39, 38, 40, 46, 0, 41, 44, 0, 
	42, 43, 0, 38, 0, 0, 45, 39, 
	0, 47, 0, 48, 49, 48, 50, 186, 
	47, 0, 48, 49, 48, 50, 186, 0, 
	48, 49, 48, 50, 186, 0, 50, 51, 
	50, 52, 58, 0, 50, 51, 50, 52, 
	58, 0, 53, 56, 0, 54, 55, 0, 
	50, 0, 0, 57, 51, 0, 59, 0, 
	60, 61, 60, 62, 180, 59, 0, 60, 
	61, 60, 62, 180, 0, 60, 61, 60, 
	62, 180, 0, 62, 63, 62, 64, 70, 
	0, 62, 63, 62, 64, 70, 0, 65, 
	68, 0, 66, 67, 0, 62, 0, 0, 
	69, 63, 0, 71, 0, 72, 73, 72, 
	74, 80, 71, 0, 72, 73, 72, 74, 
	80, 0, 72, 73, 72, 74, 80, 0, 
	75, 78, 0, 76, 77, 0, 72, 0, 
	0, 79, 73, 0, 27, 28, 27, 25, 
	29, 35, 81, 91, 123, 167, 372, 0, 
	82, 0, 83, 0, 84, 0, 85, 0, 
	86, 0, 87, 0, 88, 0, 89, 0, 
	90, 0, 38, 39, 38, 40, 46, 0, 
	92, 121, 0, 93, 94, 93, 95, 101, 
	0, 93, 94, 93, 95, 101, 0, 93, 
	94, 93, 95, 101, 0, 96, 99, 0, 
	97, 98, 0, 93, 0, 0, 100, 94, 
	0, 102, 0, 103, 104, 103, 105, 115, 
	102, 0, 103, 104, 103, 105, 115, 0, 
	103, 104, 103, 105, 115, 0, 105, 106, 
	105, 107, 109, 0, 105, 106, 105, 107, 
	109, 0, 108, 108, 108, 108, 0, 72, 
	73, 72, 108, 74, 80, 108, 108, 108, 
	108, 0, 110, 113, 0, 111, 112, 0, 
	105, 0, 0, 114, 106, 0, 116, 119, 
	0, 117, 118, 0, 103, 0, 0, 120, 
	104, 0, 122, 0, 105, 106, 105, 107, 
	109, 0, 124, 0, 125, 145, 0, 126, 
	127, 126, 128, 134, 0, 126, 127, 126, 
	128, 134, 0, 126, 127, 126, 128, 134, 
	0, 129, 132, 0, 130, 131, 0, 126, 
	0, 0, 133, 127, 0, 135, 0, 136, 
	135, 0, 136, 137, 136, 138, 139, 138, 
	138, 138, 0, 136, 137, 136, 138, 139, 
	138, 138, 138, 0, 72, 73, 72, 138, 
	74, 80, 138, 138, 138, 138, 0, 140, 
	143, 0, 141, 142, 0, 136, 0, 0, 
	144, 137, 0, 146, 147, 146, 148, 154, 
	0, 146, 147, 146, 148, 154, 0, 146, 
	147, 146, 148, 154, 0, 149, 152, 0, 
	150, 151, 0, 146, 0, 0, 153, 147, 
	0, 155, 0, 156, 155, 0, 156, 157, 
	156, 158, 164, 165, 0, 156, 157, 156, 
	158, 164, 165, 0, 159, 162, 0, 160, 
	161, 0, 156, 0, 0, 163, 157, 0, 
	72, 73, 72, 74, 80, 166, 165, 0, 
	72, 73, 72, 74, 80, 165, 0, 165, 
	0, 168, 0, 169, 0, 170, 171, 170, 
	172, 178, 0, 170, 171, 170, 172, 178, 
	0, 170, 171, 170, 172, 178, 0, 173, 
	176, 0, 174, 175, 0, 170, 0, 0, 
	177, 171, 0, 179, 0, 72, 73, 72, 
	74, 80, 179, 0, 181, 184, 0, 182, 
	183, 0, 60, 0, 0, 185, 61, 0, 
	187, 190, 0, 188, 189, 0, 48, 0, 
	0, 191, 49, 0, 193, 196, 0, 194, 
	195, 0, 23, 0, 0, 197, 24, 0, 
	199, 0, 200, 0, 201, 0, 202, 0, 
	203, 0, 204, 0, 205, 0, 206, 0, 
	206, 207, 206, 208, 214, 0, 206, 207, 
	206, 208, 214, 0, 209, 212, 0, 210, 
	211, 0, 206, 0, 0, 213, 207, 0, 
	214, 215, 214, 216, 222, 329, 0, 214, 
	215, 214, 216, 222, 329, 0, 217, 220, 
	0, 218, 219, 0, 214, 0, 0, 221, 
	215, 0, 223, 0, 224, 0, 224, 225, 
	224, 226, 323, 226, 226, 226, 0, 224, 
	225, 224, 226, 323, 226, 226, 226, 0, 
	227, 228, 227, 226, 229, 226, 294, 295, 
	226, 226, 226, 0, 227, 228, 227, 229, 
	235, 273, 0, 227, 228, 227, 229, 235, 
	273, 0, 230, 233, 0, 231, 232, 0, 
	227, 0, 0, 234, 228, 0, 236, 0, 
	237, 0, 238, 0, 239, 0, 240, 0, 
	241, 0, 242, 0, 243, 0, 244, 0, 
	244, 245, 244, 246, 252, 0, 244, 245, 
	244, 246, 252, 0, 247, 250, 0, 248, 
	249, 0, 244, 0, 0, 251, 245, 0, 
	252, 253, 252, 254, 264, 270, 0, 252, 
	253, 252, 254, 264, 270, 0, 256, 255, 
	256, 255, 256, 257, 256, 258, 214, 0, 
	256, 257, 256, 258, 214, 0, 259, 262, 
	0, 260, 261, 0, 256, 0, 0, 263, 
	257, 0, 265, 268, 0, 266, 267, 0, 
	252, 0, 0, 269, 253, 0, 271, 0, 
	256, 272, 272, 272, 0, 256, 272, 272, 
	272, 0, 274, 0, 275, 0, 275, 276, 
	275, 277, 283, 0, 275, 276, 275, 277, 
	283, 0, 278, 281, 0, 279, 280, 0, 
	275, 0, 0, 282, 276, 0, 283, 284, 
	283, 285, 291, 292, 0, 283, 284, 283, 
	285, 291, 292, 0, 286, 289, 0, 287, 
	288, 0, 283, 0, 0, 290, 284, 0, 
	256, 257, 256, 258, 214, 293, 292, 0, 
	256, 257, 256, 258, 214, 292, 0, 292, 
	0, 227, 228, 227, 226, 229, 226, 294, 
	295, 306, 226, 226, 226, 0, 227, 228, 
	227, 226, 229, 296, 226, 294, 295, 226, 
	226, 226, 0, 227, 228, 227, 226, 229, 
	297, 226, 294, 295, 226, 226, 226, 0, 
	298, 299, 298, 226, 300, 283, 226, 294, 
	295, 226, 226, 226, 0, 298, 299, 298, 
	300, 283, 235, 273, 0, 298, 299, 298, 
	300, 283, 235, 273, 0, 301, 304, 0, 
	302, 303, 0, 298, 0, 0, 305, 299, 
	0, 227, 228, 227, 226, 229, 226, 294, 
	307, 295, 226, 226, 226, 0, 227, 228, 
	227, 226, 229, 226, 294, 308, 295, 226, 
	226, 226, 0, 227, 228, 227, 226, 229, 
	226, 294, 309, 295, 226, 226, 226, 0, 
	227, 228, 227, 226, 229, 226, 294, 310, 
	295, 226, 226, 226, 0, 227, 228, 227, 
	226, 229, 226, 294, 311, 295, 226, 226, 
	226, 0, 227, 228, 227, 226, 229, 226, 
	294, 312, 295, 226, 226, 226, 0, 227, 
	228, 227, 226, 229, 226, 294, 313, 295, 
	226, 226, 226, 0, 227, 228, 227, 226, 
	229, 226, 294, 314, 295, 226, 226, 226, 
	0, 315, 316, 315, 226, 317, 252, 226, 
	294, 295, 226, 226, 226, 0, 315, 316, 
	315, 317, 252, 235, 273, 0, 315, 316, 
	315, 317, 252, 235, 273, 0, 318, 321, 
	0, 319, 320, 0, 315, 0, 0, 322, 
	316, 0, 324, 327, 0, 325, 326, 0, 
	224, 0, 0, 328, 225, 0, 329, 330, 
	329, 25, 331, 35, 81, 91, 123, 167, 
	337, 372, 0, 329, 330, 329, 25, 331, 
	35, 81, 91, 123, 167, 337, 372, 0, 
	332, 335, 0, 333, 334, 0, 329, 0, 
	0, 336, 330, 0, 338, 0, 339, 0, 
	340, 0, 341, 0, 342, 0, 343, 0, 
	344, 0, 345, 0, 346, 0, 347, 0, 
	347, 348, 347, 349, 355, 364, 0, 347, 
	348, 347, 349, 355, 364, 0, 350, 353, 
	0, 351, 352, 0, 347, 0, 0, 354, 
	348, 0, 356, 357, 356, 358, 27, 365, 
	364, 0, 356, 357, 356, 358, 27, 0, 
	356, 357, 356, 358, 27, 0, 359, 362, 
	0, 360, 361, 0, 356, 0, 0, 363, 
	357, 0, 356, 357, 356, 358, 27, 364, 
	0, 364, 0, 367, 370, 0, 368, 369, 
	0, 12, 0, 0, 371, 13, 0, 372, 
	373, 372, 1, 7, 0, 372, 373, 372, 
	1, 7, 0, 0
};

static const char _as_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 3, 0, 3, 3, 3, 0, 1, 
	1, 1, 49, 1, 49, 49, 49, 0, 
	5, 5, 5, 0, 5, 0, 5, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 1, 1, 1, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 7, 
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 52, 0, 3, 
	3, 3, 3, 0, 0, 47, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 7, 0, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 52, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 33, 33, 33, 33, 70, 
	0, 0, 0, 0, 0, 3, 0, 1, 
	1, 1, 1, 49, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 19, 19, 19, 19, 19, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 3, 0, 1, 1, 1, 1, 
	49, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	21, 21, 21, 21, 21, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 1, 
	1, 1, 0, 0, 0, 0, 0, 3, 
	0, 1, 1, 1, 1, 49, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 23, 23, 23, 
	23, 23, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 27, 27, 27, 27, 
	27, 27, 27, 27, 27, 27, 61, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 35, 35, 35, 35, 73, 0, 
	0, 0, 0, 45, 45, 45, 45, 79, 
	0, 0, 0, 0, 0, 3, 0, 1, 
	1, 1, 1, 49, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 19, 19, 19, 19, 19, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 1, 1, 1, 1, 
	1, 0, 3, 3, 3, 3, 0, 41, 
	41, 41, 0, 41, 41, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 43, 43, 43, 43, 
	43, 0, 0, 0, 0, 0, 0, 39, 
	39, 39, 39, 76, 0, 0, 0, 0, 
	0, 3, 0, 1, 1, 1, 1, 49, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 19, 
	0, 0, 0, 0, 0, 3, 0, 3, 
	3, 3, 0, 1, 1, 1, 49, 1, 
	49, 49, 49, 0, 37, 37, 37, 0, 
	37, 37, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 29, 29, 29, 29, 64, 
	0, 0, 0, 0, 0, 3, 0, 1, 
	1, 1, 1, 49, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 19, 0, 0, 0, 0, 
	0, 0, 3, 3, 0, 1, 1, 1, 
	1, 49, 49, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	25, 25, 25, 25, 25, 0, 0, 0, 
	25, 25, 25, 25, 25, 0, 0, 0, 
	0, 0, 0, 0, 0, 31, 31, 31, 
	31, 67, 0, 0, 0, 0, 0, 3, 
	0, 1, 1, 1, 1, 49, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 19, 19, 19, 
	19, 19, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 3, 0, 3, 3, 3, 0, 1, 
	1, 1, 49, 1, 49, 49, 49, 0, 
	9, 9, 9, 0, 9, 0, 9, 9, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 1, 1, 1, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 1, 1, 1, 0, 58, 3, 
	13, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	55, 3, 3, 3, 0, 11, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 1, 1, 1, 1, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 3, 3, 0, 1, 1, 1, 
	1, 49, 49, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	15, 15, 15, 15, 15, 0, 0, 0, 
	15, 15, 15, 15, 15, 0, 0, 0, 
	0, 9, 9, 9, 0, 9, 0, 9, 
	9, 0, 0, 0, 0, 0, 9, 9, 
	9, 0, 9, 0, 0, 9, 9, 0, 
	0, 0, 0, 9, 9, 9, 0, 9, 
	0, 0, 9, 9, 0, 0, 0, 0, 
	9, 9, 9, 0, 9, 0, 0, 9, 
	9, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 1, 
	1, 1, 1, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 9, 9, 9, 0, 9, 0, 9, 
	0, 9, 0, 0, 0, 0, 9, 9, 
	9, 0, 9, 0, 9, 0, 9, 0, 
	0, 0, 0, 9, 9, 9, 0, 9, 
	0, 9, 0, 9, 0, 0, 0, 0, 
	9, 9, 9, 0, 9, 0, 9, 0, 
	9, 0, 0, 0, 0, 9, 9, 9, 
	0, 9, 0, 9, 0, 9, 0, 0, 
	0, 0, 9, 9, 9, 0, 9, 0, 
	9, 0, 9, 0, 0, 0, 0, 9, 
	9, 9, 0, 9, 0, 9, 0, 9, 
	0, 0, 0, 0, 9, 9, 9, 0, 
	9, 0, 9, 0, 9, 0, 0, 0, 
	0, 9, 9, 9, 0, 9, 0, 0, 
	9, 9, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 7, 0, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 52, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 3, 3, 0, 1, 
	1, 1, 1, 49, 49, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 17, 17, 17, 17, 17, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 17, 17, 17, 17, 17, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 1, 
	1, 1, 0, 0
};

static const char _as_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1
};

static const int as_start = 372;
static const int as_first_final = 372;
static const int as_error = 0;

static const int as_en_as = 372;

#line 806 "lsmsb-as.rl"


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
struct Filter {
  Filter()
      : spill_slots(0),
        type_string(NULL),
        filter_code(LSMSB_FILTER_CODE_MAX) {
  }

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

  std::string name;  // the name of the filter (i.e. "dentry-open")
  std::vector<Constant*> constants;
  unsigned spill_slots;
  std::vector<uint32_t> ops;
  const char *type_string;  // the types of this filter's context
  unsigned filter_code;  // the enum value of the filter
};
int
main(int argc, char **argv) {
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

  
#line 1555 "lsmsb-as.cc"
	{
	cs = as_start;
	}
#line 969 "lsmsb-as.rl"
  
#line 1561 "lsmsb-as.cc"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _as_trans_keys + _as_key_offsets[cs];
	_trans = _as_index_offsets[cs];

	_klen = _as_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _as_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += ((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	cs = _as_trans_targs[_trans];

	if ( _as_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _as_actions + _as_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 623 "lsmsb-as.rl"
	{
    line_no++;
  }
	break;
	case 1:
#line 629 "lsmsb-as.rl"
	{
    start = p;
  }
	break;
	case 2:
#line 633 "lsmsb-as.rl"
	{
    current_filter = new Filter;
    current_filter->name = std::string(start, p - start);

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
	break;
	case 3:
#line 651 "lsmsb-as.rl"
	{
    filters.push_back(current_filter);
    current_filter = NULL;
    jmp_targets.clear();
  }
	break;
	case 4:
#line 657 "lsmsb-as.rl"
	{
    current_const_name = std::string(start, p - start);
  }
	break;
	case 5:
#line 661 "lsmsb-as.rl"
	{
    current_filter->constants.push_back(new ByteString(current_const_name, hex_parse(std::string(start, p - start))));
  }
	break;
	case 6:
#line 665 "lsmsb-as.rl"
	{
    current_filter->constants.push_back(new ByteString(current_const_name, std::string(start, p - start)));
  }
	break;
	case 7:
#line 669 "lsmsb-as.rl"
	{
    current_filter->constants.push_back(new U32(current_const_name, u32_parse(std::string(start, p - start))));
  }
	break;
	case 8:
#line 684 "lsmsb-as.rl"
	{
    current_filter->spill_slots = u32_parse(std::string(start, p - start));
  }
	break;
	case 9:
#line 692 "lsmsb-as.rl"
	{
    op |= reg_parse(std::string(start, p - start)) << 20;
  }
	break;
	case 10:
#line 695 "lsmsb-as.rl"
	{
    op |= reg_parse(std::string(start, p - start)) << 16;
  }
	break;
	case 11:
#line 698 "lsmsb-as.rl"
	{
    op |= reg_parse(std::string(start, p - start)) << 12;
  }
	break;
	case 12:
#line 701 "lsmsb-as.rl"
	{
    op |= imm_check(u32_parse(std::string(start, p - start)));
  }
	break;
	case 13:
#line 704 "lsmsb-as.rl"
	{
    current_filter->ops.push_back(op);
    op = 0;
  }
	break;
	case 14:
#line 708 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_LDI) << 24;
  }
	break;
	case 15:
#line 713 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_RET) << 24;
  }
	break;
	case 16:
#line 718 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_AND) << 24;
  }
	break;
	case 17:
#line 727 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_ISPREFIXOF) << 24;
  }
	break;
	case 18:
#line 736 "lsmsb-as.rl"
	{
    const std::string constant_name(start, p - start);
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
	break;
	case 19:
#line 753 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_LDC) << 24;
  }
	break;
	case 20:
#line 758 "lsmsb-as.rl"
	{
    const std::string target = std::string(start, p - start);
    const std::map<std::string, std::vector<unsigned> >::iterator i =
      jmp_targets.find(target);

    if (i == jmp_targets.end()) {
      jmp_targets[target].push_back(current_filter->ops.size());
    } else {
      i->second.push_back(current_filter->ops.size());
    }
  }
	break;
	case 21:
#line 770 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_JMP) << 24;
  }
	break;
	case 22:
#line 775 "lsmsb-as.rl"
	{
    op |= static_cast<uint32_t>(LSMSB_OPCODE_JC) << 24;
  }
	break;
	case 23:
#line 780 "lsmsb-as.rl"
	{
    const std::string target = std::string(start, p - start);
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
	break;
#line 1830 "lsmsb-as.cc"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _as_actions + _as_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 0:
#line 623 "lsmsb-as.rl"
	{
    line_no++;
  }
	break;
#line 1852 "lsmsb-as.cc"
		}
	}
	}

	_out: {}
	}
#line 970 "lsmsb-as.rl"

  if (cs == as_error) {
    fprintf(stderr, "Error line %u: parse failure around: %s\n", line_no, p);
  }

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

  const uint32_t num_filters = filters.size();
  writea(1, &num_filters, sizeof(num_filters));

  for (std::vector<Filter*>::const_iterator
       i = filters.begin(); i != filters.end(); ++i) {
    if (!(*i)->Write()) {
      fprintf(stderr, "Write failure writing to stdout\n");
      abort();
    }
  }

  return 0;
}
