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

#include "token.h"
#include "hash/hmac.h"
#include "hash/murmur3.h"
#include "base32.h"
#include "libc.h"

#include <pebble.h>

#define VERSION 0
#define ORDER 0
#define MIN(x, y) ({ \
    __typeof__(x) __x = x; \
    __typeof__(y) __y = y; \
    __x < __y ? __x : __y; \
  })

struct persist {
  uint32_t version;
  token token;
};

struct order {
  uint32_t tokens[8];
  uint8_t used;
};

static bool
hotp(const token *t, uint64_t counter, uint32_t *code)
{
  uint8_t *digest;
  size_t dlen;

#ifdef __LITTLE_ENDIAN__
  // Network byte order
  counter = (((uint64_t) htonl(counter)) << 32) + htonl(counter >> 32);
#endif

  // Create digits divisor
  uint32_t div = 1;
  for (int i = t->digits; i > 0; i--)
    div *= 10;

  // Create the HMAC
  if (!hmac(t->hash, t->secret, t->seclen,
            &counter, sizeof(counter), &digest, &dlen))
    return false;

  // Truncate
  uint32_t binary;
  uint32_t off = digest[dlen - 1] & 0xf;
  binary  = (digest[off + 0] & 0x7f) << 0x18;
  binary |= (digest[off + 1] & 0xff) << 0x10;
  binary |= (digest[off + 2] & 0xff) << 0x08;
  binary |= (digest[off + 3] & 0xff) << 0x00;
  *code = binary % div;

  free(digest);
  return true;
}

static inline int8_t
decode_digit(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  return -1;
}

static void
decode(char *str)
{
  for (size_t i = 0; str[i]; i++) {
    if (str[i] != '%')
      continue;

    int8_t u = decode_digit(str[i + 1]);
    if (u < 0)
      continue;

    int8_t l = decode_digit(str[i + 2]);
    if (l < 0)
      continue;

    if (u == 0 && l == 0)
      continue;

    size_t len = strlen(&str[i + 3]);
    str[i] = (u << 4) | l;
    memmove(&str[i + 1], &str[i + 3], len);
    str[i + 1 + len] = '\0';
  }
}

bool
token_exists(const token *t)
{
  struct persist p = { VERSION, *t };
  struct order o = {{}, 0};

  // Token cannot share an id with the order struct.
  if (t->id == ORDER)
    return false;

  // Load existing persistence order.
  if (persist_exists(ORDER)) {
    if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
      return false;
  }

  // Check if token exists.
  for (size_t i = 0; i < o.used; i++) {
    if (o.tokens[i] == t->id)
      return true;
  }
  
  return false;
}

bool
token_add(const token *t)
{
  struct persist p = { VERSION, *t };
  struct order o = {{}, 0};

  // Token cannot share an id with the order struct.
  if (t->id == ORDER)
    return false;

  // Load existing persistence order.
  if (persist_exists(ORDER)) {
    if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
      return false;
  }

  // If token exists, error.
  for (size_t i = 0; i < o.used; i++) {
    if (o.tokens[i] == t->id)
      return false;
  }
  
  // If we are full, error.
  if (o.used >= sizeof(o.tokens) / sizeof(*o.tokens))
    return false;

  // If write fails, error.
  if (persist_write_data(p.token.id, &p, sizeof(p)) != sizeof(p))
    return false;

  // Add the token to the start of the order (reverse order).
  o.tokens[o.used++] = p.token.id;

  // If order write fails, error.
  if (persist_write_data(ORDER, &o, sizeof(o)) != sizeof(o)) {
    persist_delete(p.token.id); // Remove token.
    return false;
  }

  return true;
}

bool
token_del(token *t)
{
  struct order o = {{}, 0};
  bool found = false;
 
  if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return false;

  for (int8_t i = 0; i < o.used; i++) {
    if (found)
      o.tokens[i - 1] = o.tokens[i];
    if (o.tokens[i] == t->id)
      found = true;
  }
  if (!found)
    return false;

  o.used--;
  if (persist_write_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return false;

  persist_delete(t->id);
  return true;
}

bool
token_get(int8_t pos, token *t)
{
  struct order o = {{}, 0};
  struct persist p = {VERSION};

  if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return false;
  
  if (pos < 0 || pos >= o.used)
    return false;

  if (persist_read_data(o.tokens[o.used - pos - 1], &p, sizeof(p)) != sizeof(p))
    return false;

  if (p.version != VERSION)
    return false;

  *t = p.token;
  return true;
}

uint8_t
token_count(void)
{
  struct order o = {{}, 0};

  if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return 0;

  return o.used;
}

int8_t
token_position(const token *t)
{
  struct order o = {{}, 0};

  if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return -1;

  for (int8_t i = 0; i < o.used; i++) {
    if (o.tokens[o.used - i - 1] == t->id)
      return i;
  }

  return -1;
}

bool
token_move(int8_t from, int8_t to)
{
  struct order o = {{}, 0};
  uint32_t tmp;

  if (from == to)
    return true;

  if (persist_read_data(ORDER, &o, sizeof(o)) != sizeof(o))
    return false;

  if (from < 0 || to < 0 || from >= o.used || to >= o.used)
    return false;

  from = o.used - from - 1;
  to = o.used - to - 1;
  tmp = o.tokens[from];
  if (from < to)
    memmove(&o.tokens[from], &o.tokens[from + 1],
            (to - from) * sizeof(*o.tokens));
  else
    memmove(&o.tokens[to + 1], &o.tokens[to],
            (from - to) * sizeof(*o.tokens));
  o.tokens[to] = tmp;

  return persist_write_data(ORDER, &o, sizeof(o)) == sizeof(o);
}

bool
token_code(token *t, code c[2])
{
  const uint32_t period = t->period ? t->period : 30;
  struct persist p = {VERSION, *t};
  time_t now = time(NULL);
  char tmpl[16];
  uint32_t num;

  snprintf(tmpl, sizeof(tmpl), "%%0%ud",
           MIN(t->digits, sizeof(c[0].code)));

  if (now == (time_t) - 1)
    return false;

  p.token.counter++;
  if (persist_write_data(t->id, &p, sizeof(p)) != sizeof(p))
    return false;

  switch (t->type) {
  case TOKEN_TYPE_HOTP:
    if (!hotp(t, t->counter, &num))
      return false;
    snprintf(c[0].code, sizeof(c[0].code), tmpl, num);
    c[0].start = now;
    c[0].until = now + period;
    memset(&c[1], 0, sizeof(c[1]));
    break;
  case TOKEN_TYPE_TOTP:
    now /= period;

    if (!hotp(t, now, &num))
      return false;
    snprintf(c[0].code, sizeof(c[0].code), tmpl, num);
    c[0].start = now * period;
    c[0].until = ++now * period;

    if (!hotp(t, now, &num))
      return false;
    snprintf(c[1].code, sizeof(c[1].code), tmpl, num);
    c[1].start = now * period;
    c[1].until = ++now * period;
    break;
  }

  t->counter++;
  return true;  
}

bool                        
token_parse(const char *url, token *t)
{
  bool success = false;
  char *state = NULL;
  size_t tokcnt = 0;
  char *pos = NULL;
  char *buf = NULL;

  // Set defaults.
  memset(t, 0, sizeof(*t));
  t->hash = HASH_TYPE_SHA1;
  t->period = 30;
  t->digits = 6;

  // Copy url into local buffer for modification.
  buf = __strdup(url);
  if (!buf)
    goto error;

  for (char *itr = __strtok_r(buf,  "/?&=", &state);
        itr; itr = __strtok_r(NULL, "/?&=", &state)) {
    decode(itr);
    
    switch (tokcnt++) {
    case 0: // Scheme
      if (__strcasecmp("otpauth:", itr) != 0)
        goto error;
      break;

    case 1: // Type
      if (__strcasecmp("totp", itr) == 0)
        t->type = TOKEN_TYPE_TOTP;
      else if (__strcasecmp("hotp", itr) == 0)
        t->type = TOKEN_TYPE_HOTP;
      else
        goto error;
      break;

    case 2: // Label
      t->id = murmur3_32(itr, strlen(itr));

      pos = strchr(itr, ':');
      if (pos)
        *pos++ = '\0';

      snprintf(t->name, sizeof(t->name), "%s", pos ? pos : itr);
      if (pos)
        snprintf(t->issuer, sizeof(t->issuer), "%s", itr);
      break;

    default: // Query parameters
      if (tokcnt % 2 == 0) {
        pos = itr;
        break;
      }

      if (strcmp("secret", pos) == 0) {
        int i = base32_decode(itr, t->secret, sizeof(t->secret));
        if (i < 0)
          goto error;
        t->seclen = i;
      } else if (strcmp("issuer", pos) == 0) {
        size_t lsize = strlen(itr) + strlen(t->name) + 2;
        char *tmp = malloc(lsize);
        if (!tmp)
          goto error;
        snprintf(tmp, lsize, "%s:%s", itr, t->name);
        t->id = murmur3_32(tmp, strlen(tmp));
        free(tmp);
      } else if (strcmp("algorithm", pos) == 0) {
        t->hash = hash_type_find(itr);
        if (t->hash == HASH_TYPE_UNKNOWN)
          t->hash = HASH_TYPE_SHA1;
      } else if (strcmp("digits", pos) == 0) {
        if (itr[0] == '8' && itr[1] == '\0')
          t->digits = 8;
      } else if (strcmp("counter", pos) == 0) {
        t->counter = atoi(itr);
      } else if (strcmp("period", pos) == 0) {
        int i = atoi(itr);
        if (i != 0)
          t->period = i;
      }
      break;
    }
  }

  // The secret is required.
  success = t->seclen > 0;

error:
  free(buf);
  return success;
}
