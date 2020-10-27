/*
 * Copyright (c) 2009, Shanghai Jiao Tong University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the Shanghai Jiao Tong University nor the
 *   names of its contributors may be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The core functions of TuLP-128 -- 128 bit variant of TuLP
 *
 * @author Bo Zhu, http://cis.sjtu.edu.cn/index.php/Bo_Zhu
 * @author Zheng Gong, DIES Group, University of Twente
 * @date   July 21, 2009
 */

#ifndef __TULP128_H__
#define __TULP128_H__

#include "present.h"

#define R_ROUNDS 16
#define KEY_LENGTH 160

static const uint8_t tulp128_iv1[8] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	//0
};
static const uint8_t tulp128_iv2[8] = {
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	//0
};

// the number of a binary number's digits
static uint8_t num_len(uint16_t number);

// the length is counted by bit
void tulp128(const uint8_t *message, const uint16_t msg_len, const uint8_t *key, uint8_t *tag)
{
	uint8_t i, num;
	uint8_t block1[10], block2[10];

	const uint8_t *key1 = key;
	const uint8_t *key2 = key + 10;
	uint8_t *tag1 = tag;
	uint8_t *tag2 = tag + 8;

	uint16_t num_left = msg_len;

	uint8_t temp; // for intermediate state exchange

	// first full-round encryption
	present(tulp128_iv1, key1, tag1);
	present(tulp128_iv2, key2, tag2);

	block1[8] = key[0];
	block1[9] = key[1];
	block2[8] = block1[8];
	block2[9] = block1[9];

	while (num_left >= 64) {
		block1[0] = message[0] ^ tag1[0];
		block1[1] = message[1] ^ tag1[1];
		block1[2] = message[2] ^ tag1[2];
		block1[3] = message[3] ^ tag1[3];
		block1[4] = message[4] ^ tag1[4];
		block1[5] = message[5] ^ tag1[5];
		block1[6] = message[6] ^ tag1[6];
		block1[7] = message[7] ^ tag1[7];

		block2[0] = message[0] ^ tag2[0];
		block2[1] = message[1] ^ tag2[1];
		block2[2] = message[2] ^ tag2[2];
		block2[3] = message[3] ^ tag2[3];
		block2[4] = message[4] ^ tag2[4];
		block2[5] = message[5] ^ tag2[5];
		block2[6] = message[6] ^ tag2[6];
		block2[7] = message[7] ^ tag2[7];

		// exchange the high 32 bits of left pipe and low 32 bits of right
		temp = tag1[4];
		tag1[4] = tag2[0];
		tag2[0] = temp;
		temp = tag1[5];
		tag1[5] = tag2[1];
		tag2[1] = temp;
		temp = tag1[6];
		tag1[6] = tag2[2];
		tag2[2] = temp;
		temp = tag1[7];
		tag1[7] = tag2[3];
		tag2[3] = temp;

		present_rounds(tag1, block1, R_ROUNDS, tag1);
		present_rounds(tag2, block2, R_ROUNDS, tag2);

		num_left -= 64;
		message += 8;
	}

	// the last block whose lenght is less than 64 bits
	i = 0;
	while (num_left >= 8) {
		block1[i] = message[i] ^ tag1[i];
		block2[i] = message[i] ^ tag2[i];
		num_left -= 8;
		i++;
	}
	block1[i] = message[i] & (0xFF << (8 - num_left));
	block2[i] = block1[i];
	// it doesn't matter if num_left is 0

	// pad the length of message
	num = num_len(msg_len);
	if (8 >= num_left + num) {
		num_left += num;
		block1[i] |= (msg_len << (8 - num_left));
		block2[i] = block1[i];
		if (8 == num_left) {
			block1[i] ^= tag1[i];
			block2[i] ^= tag2[i];
			num_left = 0;
			i++;
			if (8 == i) {
				i = 0;

				temp = tag1[4];
				tag1[4] = tag2[0];
				tag2[0] = temp;
				temp = tag1[5];
				tag1[5] = tag2[1];
				tag2[1] = temp;
				temp = tag1[6];
				tag1[6] = tag2[2];
				tag2[2] = temp;
				temp = tag1[7];
				tag1[7] = tag2[3];
				tag2[3] = temp;

				present_rounds(tag1, block1, R_ROUNDS, tag1);
				present_rounds(tag2, block2, R_ROUNDS, tag2);
			}
		}
	} else {
		num_left = num_left + num - 8;
		block1[i] |= (uint8_t)(msg_len >> num_left);
		block2[i] = block1[i];
		block1[i] ^= tag1[i];
		block2[i] ^= tag2[i];
		i++;
		if (8 == i) {
			i = 0;

			temp = tag1[4];
			tag1[4] = tag2[0];
			tag2[0] = temp;
			temp = tag1[5];
			tag1[5] = tag2[1];
			tag2[1] = temp;
			temp = tag1[6];
			tag1[6] = tag2[2];
			tag2[2] = temp;
			temp = tag1[7];
			tag1[7] = tag2[3];
			tag2[3] = temp;

			present_rounds(tag1, block1, R_ROUNDS, tag1);
			present_rounds(tag2, block2, R_ROUNDS, tag2);
		}
		while (num_left >= 8) {
			num_left -= 8;
			block1[i] = ((uint8_t)(msg_len >> num_left)) ^ tag1[i];
			block2[i] = ((uint8_t)(msg_len >> num_left)) ^ tag2[i];
			i++;
			if (8 == i) {
				i = 0;

				temp = tag1[4];
				tag1[4] = tag2[0];
				tag2[0] = temp;
				temp = tag1[5];
				tag1[5] = tag2[1];
				tag2[1] = temp;
				temp = tag1[6];
				tag1[6] = tag2[2];
				tag2[2] = temp;
				temp = tag1[7];
				tag1[7] = tag2[3];
				tag2[3] = temp;

				present_rounds(tag1, block1, R_ROUNDS, tag1);
				present_rounds(tag2, block2, R_ROUNDS, tag2);
			}
		}
		block1[i] = (uint8_t)(msg_len << (8 - num_left));
		block2[i] = block1[i];
	}
	
	// pad the length of key
	// the process is similar to the above
	num = num_len(KEY_LENGTH);
	if (8 >= num_left + num) {
		num_left += num;
		block1[i] |= (KEY_LENGTH << (8 - num_left));
		block2[i] |= block1[i];
		if (8 == num_left) {
			block1[i] ^= tag1[i];
			block2[i] ^= tag2[i];
			num_left = 0;
			i++;
			if (8 == i) {
				i = 0;

				temp = tag1[4];
				tag1[4] = tag2[0];
				tag2[0] = temp;
				temp = tag1[5];
				tag1[5] = tag2[1];
				tag2[1] = temp;
				temp = tag1[6];
				tag1[6] = tag2[2];
				tag2[2] = temp;
				temp = tag1[7];
				tag1[7] = tag2[3];
				tag2[3] = temp;

				present_rounds(tag1, block1, R_ROUNDS, tag1);
				present_rounds(tag2, block2, R_ROUNDS, tag2);
			}
		}
	} else {
		num_left = num_left + num - 8;
		block1[i] |= (uint8_t)(KEY_LENGTH >> num_left);
		block2[i] |= block1[i];
		block1[i] ^= tag1[i];
		block2[i] ^= tag2[i];
		i++;
		if (8 == i) {
			i = 0;

			temp = tag1[4];
			tag1[4] = tag2[0];
			tag2[0] = temp;
			temp = tag1[5];
			tag1[5] = tag2[1];
			tag2[1] = temp;
			temp = tag1[6];
			tag1[6] = tag2[2];
			tag2[2] = temp;
			temp = tag1[7];
			tag1[7] = tag2[3];
			tag2[3] = temp;

			present_rounds(tag1, block1, R_ROUNDS, tag1);
			present_rounds(tag2, block2, R_ROUNDS, tag2);
		}
		while (num_left >= 8) {
			num_left -= 8;
			block1[i] = (uint8_t)((KEY_LENGTH >> num_left) ^ tag1[i]);
			block2[i] = (uint8_t)((KEY_LENGTH >> num_left) ^ tag2[i]);
			i++;
			if (8 == i) {
				i = 0;

				temp = tag1[4];
				tag1[4] = tag2[0];
				tag2[0] = temp;
				temp = tag1[5];
				tag1[5] = tag2[1];
				tag2[1] = temp;
				temp = tag1[6];
				tag1[6] = tag2[2];
				tag2[2] = temp;
				temp = tag1[7];
				tag1[7] = tag2[3];
				tag2[3] = temp;

				present_rounds(tag1, block1, R_ROUNDS, tag1);
				present_rounds(tag2, block2, R_ROUNDS, tag2);
			}
		}
		block1[i] = (uint8_t)(KEY_LENGTH << (8 - num_left));
		block2[i] = block1[i];
	}

	// pad 1000...
	if (i > 0 || num_left > 0) {
		block1[i] |= (1 << (7 - num_left));
		block2[i] = block1[i];
		block1[i] ^= tag1[i];
		block2[i] ^= tag2[i];
		i++;
		if (8 == i) {
			i = 0;

			temp = tag1[4];
			tag1[4] = tag2[0];
			tag2[0] = temp;
			temp = tag1[5];
			tag1[5] = tag2[1];
			tag2[1] = temp;
			temp = tag1[6];
			tag1[6] = tag2[2];
			tag2[2] = temp;
			temp = tag1[7];
			tag1[7] = tag2[3];
			tag2[3] = temp;

			present_rounds(tag1, block1, R_ROUNDS, tag1);
			present_rounds(tag2, block2, R_ROUNDS, tag2);
		}
	}
	while (i > 0 && i < 8) {
		block1[i] = tag1[i];
		block2[i] = tag2[i];
		i++;
	}

	temp = tag1[4];
	tag1[4] = tag2[0];
	tag2[0] = temp;
	temp = tag1[5];
	tag1[5] = tag2[1];
	tag2[1] = temp;
	temp = tag1[6];
	tag1[6] = tag2[2];
	tag2[2] = temp;
	temp = tag1[7];
	tag1[7] = tag2[3];
	tag2[3] = temp;

	present_rounds(tag1, block1, R_ROUNDS, tag1);
	present_rounds(tag2, block2, R_ROUNDS, tag2);

	// last full-round encryption
	present(tag1, key1, tag1);
	present(tag2, key2, tag2);
}

static uint8_t num_len(uint16_t number)
{
	uint8_t i = 0;

	while (number > 0) {
		number >>= 1;
		i++;
	}
	
	return i;
}

#endif /* __TULP_H__ */
