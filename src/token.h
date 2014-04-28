/*
 * FreeOTP
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2014  Nathaniel McCallum, Red Hat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "hash/hash.h"

#define TOKEN_TYPE_TOTP 0
#define TOKEN_TYPE_HOTP 1

typedef struct token token;
typedef struct code code;

struct token {
  char issuer[64];
  char name[64];
  uint8_t secret[64];
  uint64_t counter;
  uint32_t id;
  uint8_t seclen;
  uint8_t period;
  uint8_t digits;
  uint8_t hash; /* We don't use the enum so we can specify storage. */
  uint8_t type;
};

struct code {
  char code[9];
  time_t start;
  time_t until;
};

bool
token_exists(const token *t);

bool
token_add(const token *t);

bool
token_del(token *t);

bool
token_get(int8_t pos, token *t);

uint8_t
token_count(void);

int8_t
token_position(const token *t);

bool
token_move(int8_t from, int8_t to);

bool
token_code(token *t, code c[2]);

bool
token_parse(const char *url, token *t);
