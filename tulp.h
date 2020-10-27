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
 * The core function of TuLP -- Tunable Lightweight MAC based on PRESENT
 *
 * @author Bo Zhu, http://cis.sjtu.edu.cn/index.php/Bo_Zhu
 * @author Zheng Gong, DIES Group, University of Twente
 * @date   July 21, 2009
 */

#ifndef __TULP_H__
#define __TULP_H__

#include "present.h"

#define R_ROUNDS 16
#define KEY_LENGTH 80

static const uint8_t tulp_iv[8] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	//0
};

// the number of a binary number's digits
static uint8_t num_len(uint16_t number);

// the length is counted by bit
void tulp(const uint8_t *message, const uint16_t msg_len, const uint8_t *key, uint8_t *tag)
{
	uint8_t i, num;
	uint8_t block[10];

	uint16_t num_left = msg_len;

	// first full-round encryption
	present(tulp_iv, key, tag);

	block[8] = key[0];
	block[9] = key[1];

	while (num_left >= 64) {
		block[0] = message[0] ^ tag[0];
		block[1] = message[1] ^ tag[1];
		block[2] = message[2] ^ tag[2];
		block[3] = message[3] ^ tag[3];
		block[4] = message[4] ^ tag[4];
		block[5] = message[5] ^ tag[5];
		block[6] = message[6] ^ tag[6];
		block[7] = message[7] ^ tag[7];

		present_rounds(tag, block, R_ROUNDS, tag);

		num_left -= 64;
		message += 8;
	}

	// the last block whose lenght is less than 64 bits
	i = 0;
	while (num_left >= 8) {
		block[i] = message[i] ^ tag[i];
		num_left -= 8;
		i++;
	}
	block[i] = message[i] & (0xFF << (8 - num_left));
	// it doesn't matter if num_left is 0

	// pad the length of message
	// may be a little complex...
	num = num_len(msg_len);
	if (8 >= num_left + num) {
		num_left += num;
		block[i] |= (msg_len << (8 - num_left));
		if (8 == num_left) {
			block[i] ^= tag[i];
			num_left = 0;
			i++;
			if (8 == i) {
				i = 0;
				present_rounds(tag, block, R_ROUNDS, tag);
			}
		}
	} else {
		num_left = num_left + num - 8;
		block[i] |= (uint8_t)(msg_len >> num_left);
		block[i] ^= tag[i];
		i++;
		if (8 == i) {
			i = 0;
			present_rounds(tag, block, R_ROUNDS, tag);
		}
		while (num_left >= 8) {
			num_left -= 8;
			block[i] = (uint8_t)((msg_len >> num_left) ^ tag[i]);
			i++;
			if (8 == i) {
				i = 0;
				present_rounds(tag, block, R_ROUNDS, tag);
			}
		}
		block[i] = (uint8_t)(msg_len << (8 - num_left));
	}
	
	// pad the length of key
	// the process is similar to the above
	num = num_len(KEY_LENGTH);
	if (8 >= num_left + num) {
		num_left += num;
		block[i] |= (KEY_LENGTH << (8 - num_left));
		if (8 == num_left) {
			block[i] ^= tag[i];
			num_left = 0;
			i++;
			if (8 == i) {
				i = 0;
				present_rounds(tag, block, R_ROUNDS, tag);
			}
		}
	} else {
		num_left = num_left + num - 8;
		block[i] |= (uint8_t)(KEY_LENGTH >> num_left);
		block[i] ^= tag[i];
		i++;
		if (8 == i) {
			i = 0;
			present_rounds(tag, block, R_ROUNDS, tag);
		}
		while (num_left >= 8) {
			num_left -= 8;
			block[i] = (uint8_t)((KEY_LENGTH >> num_left) ^ tag[i]);
			i++;
			if (8 == i) {
				i = 0;
				present_rounds(tag, block, R_ROUNDS, tag);
			}
		}
		block[i] = (uint8_t)(KEY_LENGTH << (8 - num_left));
	}

	// pad 1000...
	if (i > 0 || num_left > 0) {
		block[i] |= (1 << (7 - num_left));
		block[i] ^= tag[i];
		i++;
		if (8 == i) {
			i = 0;
			present_rounds(tag, block, R_ROUNDS, tag);
		}
	}
	while (i > 0 && i < 8) {
		block[i] = tag[i];
		i++;
	}
	present_rounds(tag, block, R_ROUNDS, tag);

	// last full-round encryption
	present(tag, key, tag);
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
