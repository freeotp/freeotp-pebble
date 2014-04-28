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

#include "libc.h"

#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

static int
lower(int c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A' + 'a';

  return c;
}

int
__strcasecmp(const char *a, const char *b)
{
  return __strncasecmp(a, b, 0);
}

  int
__strncasecmp(const char *a, const char *b, size_t size)
{
  if (a == b)
    return 0;

  if (a == NULL)
    return -1;

  if (b == NULL)
    return 1;

  for (uint32_t i = 0; size == 0 || i < size; i++) {
    char aa = lower((int) a[i]);
    char bb = lower((int) b[i]);

    if (aa == bb) {
      if (aa == '\0')
        return 0;
      continue;
    }

    return aa - bb;
  }

  return 0;
}

char *
__strdup(const char *str)
{
  char *tmp;

  tmp = malloc(strlen(str) + 1);
  if (!tmp)
    return NULL;

  strcpy(tmp, str);
  return tmp;
}

char *
__strtok_r(char *buf, const char *sep, char **lasts)
{
  if (!buf)
    buf = *lasts;

  while (buf && *buf && strchr(sep, *buf))
    *buf++ = '\0';

  if (!buf || !*buf)
    return NULL;

  for (*lasts = buf; **lasts; (*lasts)++) {
    if (strchr(sep, **lasts)) {
      *(*lasts)++ = '\0';
      break;
    }
  }

  return buf;
}
