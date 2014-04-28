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

#include "ui/menu.h"
#include "msg.h"

static void
msg_received(DictionaryIterator *iterator, void *context)
{
  bool added;
  
  on_message(iterator, &added);
  
  if (!added)
    return;

  // Success. Rewind to the top of the stack and reload.
  while (window_stack_get_top_window() != context)
    window_stack_pop(true);
  menu_reload(context);
}

int
main(void)
{
  AppMessageResult rslt;
  Window *top;
  
  top = menu_create();
  if (!top) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failed to create window!");
    return 1;
  }

  app_message_set_context(top);
  app_message_register_inbox_received(msg_received);
  rslt = app_message_open(app_message_inbox_size_maximum(),
                          app_message_outbox_size_maximum());
  if (rslt != APP_MSG_OK) {
    APP_LOG(APP_LOG_LEVEL_ERROR, "Failed to open message boxes: %d!", rslt);
    return 1;
  }

  window_stack_push(top, true);

  app_event_loop();
     
  app_message_deregister_callbacks();
  window_destroy(top);
  return 0;
}

