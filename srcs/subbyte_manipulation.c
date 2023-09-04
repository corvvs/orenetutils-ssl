#include "ft_ssl_md5_internal.h"

void	set_bit_at(uint8_t* mem, uint64_t bit_pos, uint8_t bit) {
	uint64_t	octet_pos = bit_pos / OCTET_BIT_SIZE;
	uint8_t		octet_bit_pos = bit_pos % OCTET_BIT_SIZE;

	// mem[octet_pos] &= ~(1 << (octet_bit_pos));
	// mem[octet_pos] |= (bit << (octet_bit_pos));
	mem[octet_pos] &= ~(1 << (OCTET_BIT_SIZE - octet_bit_pos - 1));
	mem[octet_pos] |= (bit << (OCTET_BIT_SIZE - octet_bit_pos - 1));
}

void	subbyte_memcpy(uint8_t* dst, const uint8_t* src, uint8_t bit_from, uint8_t bit_to) {
	if (bit_from > bit_to) {
		DEBUGFATAL("bit: [%u, %u)", bit_from, bit_to);
	}
	if (OCTET_BIT_SIZE < bit_to) {
		DEBUGFATAL("bit: [%u, %u)", bit_from, bit_to);
	}
	const uint8_t 	copy_mask = FT_MASK(bit_to) - FT_MASK(bit_from);
	// const uint8_t 	copy_mask = FT_MASK(OCTET_BIT_SIZE - bit_from) - FT_MASK(OCTET_BIT_SIZE - bit_to);
	*dst &= ~copy_mask;
	*dst |= copy_mask & *src;
	DEBUGOUT("bit: [%u, %u)", bit_from, bit_to);
}

void	subbyte_memset(uint8_t* mem, const uint8_t bit, uint8_t bit_from, uint8_t bit_to) {
	if (bit_from > bit_to) {
		DEBUGFATAL("bit: [%u, %u)", bit_from, bit_to);
	}
	if (OCTET_BIT_SIZE < bit_to) {
		DEBUGFATAL("bit: [%u, %u)", bit_from, bit_to);
	}
	// const uint8_t 	copy_mask = FT_MASK(bit_to) - FT_MASK(bit_from);
	const uint8_t 	copy_mask = FT_MASK(OCTET_BIT_SIZE - bit_from) - FT_MASK(OCTET_BIT_SIZE - bit_to);
	if (bit) {
		*mem |= copy_mask;
	} else {
		*mem &= ~copy_mask;
	}
}