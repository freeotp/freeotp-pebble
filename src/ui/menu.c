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

#include <pebble.h>
#include "../token.h"
#include "../libc.h"
#include "code.h"

typedef struct {
  int8_t from;
  int8_t to;
} moving;

typedef struct {
  MenuLayer *ml;
  TextLayer *tl;
  GBitmap *icon;
  Window *code;
  moving moving;
} user_data;

static void
menu_draw_row(GContext *ctx, const Layer *cell_layer, MenuIndex *cell_index, void *callback_context)
{
  user_data *ud = callback_context;
  bool success;
  token t;

  if (ud->moving.to == cell_index->row)
    success = token_get(ud->moving.from, &t);
  else if (ud->moving.from < ud->moving.to && cell_index->row >= ud->moving.from && cell_index->row < ud->moving.to)
    success = token_get(cell_index->row + 1, &t);
  else if (ud->moving.from > ud->moving.to && cell_index->row > ud->moving.to && cell_index->row <= ud->moving.from)
    success = token_get(cell_index->row - 1, &t);
  else
    success = token_get(cell_index->row, &t);
  
  if (success)
    menu_cell_basic_draw(ctx, cell_layer, t.issuer, t.name, ud->moving.to == cell_index->row ? ud->icon : NULL);
}

static uint16_t
menu_get_num_rows(MenuLayer *menu_layer, uint16_t section_index, void *callback_context)
{
  user_data *ud = callback_context;
  uint16_t count = token_count();
  
  layer_set_hidden(menu_layer_get_layer(ud->ml), count == 0);
  layer_set_hidden(text_layer_get_layer(ud->tl), count != 0);
  return count;
}

static void
menu_select_click(MenuLayer *menu_layer, MenuIndex *cell_index, void *callback_context)
{
  user_data *ud = callback_context;
  token t;
 
  if (ud->moving.from >= 0) {
    if (ud->moving.from != ud->moving.to)
      token_move(ud->moving.from, ud->moving.to);
    ud->moving = (moving) { -1, -1 };
    menu_layer_reload_data(menu_layer);
    return;
  }

  if (token_get(cell_index->row, &t)) {
    ud->code = code_create(&t);
    if (ud->code)
      window_stack_push(ud->code, true);
  }
}

static void
menu_select_long_click(MenuLayer *menu_layer, MenuIndex *cell_index, void *callback_context)
{
  user_data *ud = callback_context;
  
  if (ud->moving.from < 0) {
    ud->moving = (moving) { (int8_t) cell_index->row, (int8_t) cell_index->row };
    menu_layer_reload_data(menu_layer);
  } else
    menu_select_click(menu_layer, cell_index, callback_context);
}

static void
menu_selection_changed(MenuLayer *menu_layer, MenuIndex new_index,
                       MenuIndex old_index, void *callback_context)
{
  user_data *ud = callback_context;

  if (ud->moving.to == old_index.row) {
    ud->moving.to = new_index.row;
    menu_layer_reload_data(menu_layer);
  }
}

static void
load(Window *window)
{
  Layer *rl = window_get_root_layer(window);
  user_data *ud;
  Layer *l;
  GRect f;
  GSize s;
 
  ud = (user_data*) malloc(sizeof(*ud));
  if (!ud)
    return;
  *ud = (user_data) { .moving = {-1, -1} };
  window_set_user_data(window, ud);
  
  ud->icon = gbitmap_create_with_resource(RESOURCE_ID_MOVE);

  ud->tl = text_layer_create(layer_get_bounds(rl));
  text_layer_set_text(ud->tl, "Use FreeOTP on your mobile device to add tokens.");
  text_layer_set_text_alignment(ud->tl, GTextAlignmentCenter);
  text_layer_set_overflow_mode(ud->tl, GTextOverflowModeWordWrap);
  s = text_layer_get_content_size(ud->tl);
  l = text_layer_get_layer(ud->tl);
  f = layer_get_frame(l);
  f.origin.y = (f.size.h - s.h) / 2;
  f.size.h = s.h;
  layer_set_frame(l, f);
  layer_set_hidden(l, true);
  
  ud->ml = menu_layer_create(layer_get_bounds(rl));
  layer_set_hidden(menu_layer_get_layer(ud->ml), false);
  menu_layer_set_click_config_onto_window(ud->ml, window);
  menu_layer_set_callbacks(ud->ml, ud, (MenuLayerCallbacks) {
    .draw_row = menu_draw_row,
    .get_num_rows = menu_get_num_rows,
    .select_click = menu_select_click,
    .select_long_click = menu_select_long_click,
    .selection_changed = menu_selection_changed
  });

  layer_add_child(rl, menu_layer_get_layer(ud->ml));
  layer_add_child(rl, text_layer_get_layer(ud->tl));
}

static void
appear(Window *window)
{
  user_data *ud = (user_data *) window_get_user_data(window);
  if (ud->code) {
    window_destroy(ud->code);
    ud->code = NULL;
  }

  menu_layer_reload_data(ud->ml);
}

static void
unload(Window *window)
{
  user_data *ud = (user_data *) window_get_user_data(window);
  window_set_user_data(window, NULL);
  menu_layer_destroy(ud->ml);
  text_layer_destroy(ud->tl);
  gbitmap_destroy(ud->icon);
  free(ud);
}

Window *
menu_create(void)
{
  Window *w;

  w = window_create();
  window_set_window_handlers(w, (WindowHandlers) {
    .load = load,
    .appear = appear,
    .unload = unload,
  });

  return w;
}

void
menu_reload(Window *window)
{
  user_data *ud = window_get_user_data(window);
  menu_layer_reload_data(ud->ml);
}
