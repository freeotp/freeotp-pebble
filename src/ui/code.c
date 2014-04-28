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

#include "code.h"

#define count(a) (sizeof(a) / sizeof(*(a)))
#define abs(v) ({ __typeof__(v) __x = v; __x < 0 ? 0 - __x : __x; })

typedef struct {
  token token;
  code codes[2];
  struct {
    ActionBarLayer *abl;
    TextLayer *issuer;
    TextLayer *name;
    TextLayer *code;
    Layer *progress;
  } layers;
  struct {
    GBitmap *delete;
    GBitmap *cancel;
  } icons;
  AppTimer *timer;
} user_data;

static inline GRect
rect(Layer *layer, uint8_t width, int8_t height)
{
  GRect f = layer_get_frame(layer);
  int16_t h = f.size.h * abs(height) / 100; 
  f.origin.x = 0;
  f.origin.y = height < 0 ? f.size.h - h : 0;
  f.size.w = f.size.w * width / 100;
  f.size.h = h;
  return f;
}

static time_t
last(const user_data *ud)
{
  time_t last = 0;
  for (size_t j = count(ud->codes); j > 0; j--) {
    last = ud->codes[j - 1].until;
    if (last != 0)
      break;
  }

  return last;
}

static const code *
active(const user_data *ud, time_t now)
{
  for (size_t i = 0; i < count(ud->codes); i++) {
    const code *c = &ud->codes[i];
    
    if (now >= c->start && now < c->until)
      return c;
  }

  return NULL;
}

static void
progress(Layer *layer, GContext *ctx)
{
  Window *w = layer_get_window(layer);
  user_data *ud = window_get_user_data(w);

  graphics_context_set_stroke_color(ctx, GColorBlack);
  graphics_context_set_fill_color(ctx, GColorBlack);  
  
  graphics_draw_round_rect(ctx, rect(layer, 100, 100), 3);

  time_t now = time(NULL);
  const code *c = active(ud, now);
  if (c) {
    uint8_t ptop = 100 - (now - c->start) * 100 / (c->until - c->start);
    uint8_t pbot = 100 - (now - ud->codes[0].start) * 100 / (last(ud) - ud->codes[0].start);
    graphics_fill_rect(ctx, rect(layer, ptop, 50), 3, ptop > 99 ? GCornersTop : GCornerTopLeft);
    graphics_fill_rect(ctx, rect(layer, pbot, -50), 3, pbot > 99 ? GCornersBottom : GCornerBottomLeft);
  }
}

static void
update_code(const user_data *ud)
{
  const code *c = active(ud, time(NULL));
  if (!c)
    return;

  text_layer_set_text(ud->layers.code, c->code);
}

static void
up(ClickRecognizerRef recognizer, void *context)
{
  user_data *ud = context;
  if (layer_get_hidden(action_bar_layer_get_layer(ud->layers.abl)))
    return;

  token_del(&ud->token);
  window_stack_pop(true);
}

static void
down(ClickRecognizerRef recognizer, void *context)
{
  user_data *ud = context;
  layer_set_hidden(action_bar_layer_get_layer(ud->layers.abl), true);
}

static void
long_click(ClickRecognizerRef recognizer, void *context)
{
  user_data *ud = context;
  layer_set_hidden(action_bar_layer_get_layer(ud->layers.abl), false);
}

static void
click_config_provider(void *context)
{
  window_single_click_subscribe(BUTTON_ID_UP, up);
  window_single_click_subscribe(BUTTON_ID_DOWN, down);
  window_long_click_subscribe(BUTTON_ID_SELECT, 0, long_click, NULL);
}

static void
load(Window *window)
{
  user_data *ud = window_get_user_data(window);
  Layer *l = window_get_root_layer(window);
  GRect f = layer_get_frame(l);

  // Set padding.
  f.origin.x += 6;
  f.size.w -= 12;
  
  // Setup progress.
  f.origin.y = (f.size.h - 28 - 28 - 22) / 2 - 8;
  f.size.h = 8;
  ud->layers.progress = layer_create(f);
  layer_set_update_proc(ud->layers.progress, progress);
  
  // Setup code.
  f.origin.y += 16;
  f.size.h = 28;
  ud->layers.code = text_layer_create(f);
  text_layer_set_font(ud->layers.code,
                      fonts_get_system_font(FONT_KEY_DROID_SERIF_28_BOLD));
  update_code(ud);

  // Setup issuer.
  f.origin.y += f.size.h;
  f.size.h = 28;
  ud->layers.issuer = text_layer_create(f);
  text_layer_set_overflow_mode(ud->layers.issuer, GTextOverflowModeTrailingEllipsis);
  text_layer_set_font(ud->layers.issuer,
                      fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD));
  text_layer_set_text(ud->layers.issuer, ud->token.issuer);
  
  // Setup name.
  f.origin.y += f.size.h;
  f.size.h = 22;
  ud->layers.name = text_layer_create(f);
  text_layer_set_overflow_mode(ud->layers.name, GTextOverflowModeTrailingEllipsis);
  text_layer_set_font(ud->layers.name,
                      fonts_get_system_font(FONT_KEY_GOTHIC_18));
  text_layer_set_text(ud->layers.name, ud->token.name);
  
  // Add layers.
  layer_add_child(l, text_layer_get_layer(ud->layers.issuer));
  layer_add_child(l, text_layer_get_layer(ud->layers.name));
  layer_add_child(l, text_layer_get_layer(ud->layers.code));
  layer_add_child(l, ud->layers.progress);

  // Setup action bar.
  ud->layers.abl = action_bar_layer_create();
  action_bar_layer_set_context(ud->layers.abl, ud);
  action_bar_layer_set_click_config_provider(ud->layers.abl, click_config_provider);
  action_bar_layer_set_icon(ud->layers.abl, BUTTON_ID_UP, ud->icons.delete);
  action_bar_layer_set_icon(ud->layers.abl, BUTTON_ID_DOWN, ud->icons.cancel);
  action_bar_layer_add_to_window(ud->layers.abl, window);
  layer_set_hidden(action_bar_layer_get_layer(ud->layers.abl), true);
}


static void
tick(void *data)
{
  user_data *ud = data;

  if (time(NULL) >= last(ud)) {
    window_stack_pop(true);
    ud->timer = NULL;
    return;
  }

  update_code(ud);
  layer_mark_dirty(ud->layers.progress);
  ud->timer = app_timer_register(1000, tick, data);
}

static void
appear(Window *window)
{
  user_data *ud = window_get_user_data(window);
  ud->timer = app_timer_register(1000, tick, ud);
}

static void
disappear(Window *window)
{
  user_data *ud = window_get_user_data(window);
  if (ud->timer) {
    app_timer_cancel(ud->timer);
    ud->timer = NULL;
  }
}

static void
user_data_free(user_data *ud)
{
  if (!ud)
    return;

  if (ud->layers.abl) {
    layer_remove_from_parent(action_bar_layer_get_layer(ud->layers.abl));
    action_bar_layer_destroy(ud->layers.abl);
  }

  if (ud->layers.issuer) {
    layer_remove_from_parent(text_layer_get_layer(ud->layers.issuer));
    text_layer_destroy(ud->layers.issuer);
  }

  if (ud->layers.name) {
    layer_remove_from_parent(text_layer_get_layer(ud->layers.name));
    text_layer_destroy(ud->layers.name);
  }

  if (ud->layers.code) {
    layer_remove_from_parent(text_layer_get_layer(ud->layers.code));
    text_layer_destroy(ud->layers.code);
  }

  if (ud->layers.progress)
    layer_destroy(ud->layers.progress);

  if (ud->icons.cancel)
    gbitmap_destroy(ud->icons.cancel);

  if (ud->icons.delete)
    gbitmap_destroy(ud->icons.delete);
  
  free(ud);
}

static user_data *
user_data_create(token *t)
{
  user_data *ud = malloc(sizeof(*ud));
  if (!ud)
    goto error;
  
  memset(ud, 0, sizeof(*ud));
  ud->token = *t;

  if (!token_code(t, ud->codes))
    goto error;

  ud->icons.cancel = gbitmap_create_with_resource(RESOURCE_ID_CANCEL);
  if (!ud->icons.cancel)
    goto error;

  ud->icons.delete = gbitmap_create_with_resource(RESOURCE_ID_DELETE);
  if (!ud->icons.delete)
    goto error;
  
  return ud;

error:
  user_data_free(ud);
  return NULL;
}

static void
unload(Window *window)
{
  user_data_free(window_get_user_data(window));
}


Window *
code_create(token *t)
{
  user_data *ud;
  Window *w;

  ud = user_data_create(t);
  if (!ud)
    return NULL;

  w = window_create();
  if (!w) {
    user_data_free(ud);
    return NULL;
  }

  window_set_user_data(w, ud);
  window_set_click_config_provider_with_context(w, click_config_provider, ud);
  window_set_window_handlers(w, (WindowHandlers) {
    .load = load,
    .appear = appear,
    .disappear = disappear,
    .unload = unload
  });

  return w;
}

