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

#include "msg.h"
#include "ui/menu.h"
#include "token.h"
#include "libc.h"

#define MSG_MAX     5
#define MSG_TIMEOUT 10

struct message {
  char *hash;
  char *buffer;
  size_t size;
  time_t start;
};

struct message messages[MSG_MAX];

static void
message_free(struct message *msg)
{
  if (!msg)
    return;

  free(msg->hash);
  free(msg->buffer);
  memset(msg, 0, sizeof(struct message));
}

static void
respond(const char *hash, const char *msg, bool success)
{
  DictionaryIterator *output;

   // Create the response message.
  if (app_message_outbox_begin(&output) != APP_MSG_OK) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failure starting reply!");
    return;
  }

  // Save the hash in the response.
  if (dict_write_cstring(output, KEY_HASH, hash) != DICT_OK) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failure setting hash!");
    return;
  }
  
  // Save the message.
  if (msg && dict_write_cstring(output, KEY_MESSAGE, msg) != DICT_OK)
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failure setting message!");  

  // Save the success.
  if (dict_write_uint8(output, KEY_SUCCESS, success) != DICT_OK)
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failure setting success!");

  // Send it.
  if (app_message_outbox_send() != APP_MSG_OK)
    APP_LOG(APP_LOG_LEVEL_ERROR, "Error sending response!");
}

static void
tick(void *data)
{
  time_t expire = time(NULL) - MSG_TIMEOUT;

  for (size_t i = 0; i < MSG_MAX; i++) {
    if (messages[i].start < expire)
      message_free(&messages[i]);
  }
}

static Tuple *
get(DictionaryIterator *iterator, uint32_t key, TupleType type)
{
  Tuple *tuple;

  // Get the ID.
  tuple = dict_find(iterator, key);
  if (!tuple) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Key not found (%u)!", (unsigned) key);
    return NULL;
  }

  // Make sure it is a string.
  if (tuple->type != type) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Invalid value type (%u:%d)!",
            (unsigned) key, tuple->type);
    return NULL;
  }

  return tuple;
}

static size_t
get_uint(DictionaryIterator *iterator, uint32_t key)
{
  Tuple *tuple;
  
  tuple = get(iterator, key, TUPLE_UINT);
  if (tuple) {
    switch (tuple->length) {
    case 1:
      return tuple->value->uint8;
    case 2:
      return tuple->value->uint16;
    case 4:
      return tuple->value->uint32;
    }
  }

  return 0;
}

static bool
get_slot(DictionaryIterator *iterator, struct message **out)
{
  struct message *msg = NULL;
  Tuple *tuple = NULL;
  
  // Get the hash.
  tuple = get(iterator, KEY_HASH, TUPLE_CSTRING);
  if (!tuple) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Invalid message (hash)!");
    return false;
  }

  // Get a message slot.
  for (size_t i = 0; i < MSG_MAX; i++) {
    // Get an empty message slot.
    if (messages[i].hash == NULL)
      msg = &messages[i];

    // Get the existing message slot.
    else if (strcmp(messages[i].hash, tuple->value->cstring) == 0) {
      msg = &messages[i];
      break;
    }
  }
  
  // No existing message found and no empty slots.
  if (!msg) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Too many outstanding messages!");
    respond(tuple->value->cstring, "The Pebble is busy; try again.", false);
    return false;
  }

  // If we got an empty slot, fill in the hash and start time.
  if (!msg->hash) {
    app_timer_register(MSG_TIMEOUT * 1000, tick, NULL);
    msg->start = time(NULL);
    msg->hash = __strdup(tuple->value->cstring);
    if (!msg->hash) {
      APP_LOG(APP_LOG_LEVEL_ERROR, "Out of memory!");
      respond(tuple->value->cstring, "The Pebble is out of memory.", false);
      return false;
    }
  }
  
  *out = msg;
  return true;
}

static bool
copy_fragment(DictionaryIterator *iterator, struct message *msg)
{
  size_t offset = 0;
  size_t newsize;
  Tuple *tuple;
  
  // Get offset and data.
  offset = get_uint(iterator, KEY_OFFSET);
  tuple = get(iterator, KEY_MESSAGE, TUPLE_CSTRING);
  if (!tuple) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Invalid message (msg)!");
    respond(msg->hash, "Invalid message value!", false);
    return false;
  }

  // Allocate buffer if needed.
  newsize = offset + tuple->length - 1;
  if (msg->size < newsize) {
    char *tmp = malloc(newsize);
    if (!tmp) {
      APP_LOG(APP_LOG_LEVEL_ERROR, "Out of memory!");
      respond(msg->hash, "The Pebble is out of memory.", false);
      return false;
    }

    if (msg->size > 0)
      memmove(tmp, msg->buffer, msg->size);
   
    free(msg->buffer); 
    msg->buffer = tmp;
    msg->size = newsize;
  }

  // Copy in this block of data.
  memmove(msg->buffer + offset, tuple->value->cstring, tuple->length - 1);
  return true;
}

static bool
validate(struct message *msg)
{
  const hash_spec *spec;
  hash_type type;
  hash_ctx *ctx;
  uint8_t *hsh;
  char *hex;
  char *sep;
  bool ret;
 
  sep = strchr(msg->hash, ':');
  if (!sep)
    return false;
  
  type = hash_type_findn(msg->hash, sep - msg->hash);
  if (type == HASH_TYPE_UNKNOWN)
    return false;

  spec = hash_spec_get(type);
  if (!spec)
    return false;

  ctx = malloc(spec->ctx);
  hsh = malloc(spec->hash);
  hex = malloc(spec->hash * 2);
  if (!ctx || !hsh || !hex) {
    free(ctx);
    free(hsh);
    free(hex);
    return false;
  }

  spec->init(ctx);
  spec->update(ctx, msg->buffer, msg->size);
  spec->finish(ctx, hsh);
  hash_to_hex(hsh, spec->hash, hex);

  ret = __strncasecmp(++sep, hex, spec->hash * 2) == 0;
  free(ctx);
  free(hsh);
  free(hex);
  return ret;
}

void
on_message(DictionaryIterator *iterator, bool *added)
{
  struct message *msg = NULL;
  token token;
  
  *added = false;
 
  if (!get_slot(iterator, &msg))
    return;

  if (!copy_fragment(iterator, msg))
    goto egress;

  if (!validate(msg))
    return;

  if (!token_parse(msg->buffer, &token)) {
    respond(msg->hash, "Error parsing URI!", false);
    goto egress;
  }
  
  if (!token_exists(&token)) {
    *added = token_add(&token);
    if (!*added) {
      respond(msg->hash, "Error adding token!", false);
      goto egress;
    }
  }

  respond(msg->hash, NULL, true);

egress:
  message_free(msg);
}
