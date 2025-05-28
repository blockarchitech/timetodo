/*
 *    Copyright 2025 blockarchitech
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <pebble.h>
#include "timetodo.h"

static Window *s_main_window;
static TextLayer *s_body_layer, *s_title_layer;
static BitmapLayer *s_icon_layer;

static GBitmap *s_icon_bitmap;

static void window_load(Window *window)
{
  Layer *window_layer = window_get_root_layer(window);
  GRect bounds = layer_get_bounds(window_layer);

  s_icon_bitmap = gbitmap_create_with_resource(RESOURCE_ID_CONFIG_REQUIRED);
  GRect bitmap_bounds = gbitmap_get_bounds(s_icon_bitmap);

  const GEdgeInsets icon_insets = GEdgeInsets(
      (bounds.size.h - bitmap_bounds.size.h) / 2,
      (bounds.size.w - bitmap_bounds.size.w) / 2);
  s_icon_layer = bitmap_layer_create(grect_inset(bounds, icon_insets));
  bitmap_layer_set_bitmap(s_icon_layer, s_icon_bitmap);
  bitmap_layer_set_compositing_mode(s_icon_layer, GCompOpSet);
  layer_add_child(window_layer, bitmap_layer_get_layer(s_icon_layer));

  const GEdgeInsets title_insets = {.top = 10};
  s_title_layer = text_layer_create(grect_inset(bounds, title_insets));
  text_layer_set_text(s_title_layer, DIALOG_CONFIG_WINDOW_APP_NAME);
  text_layer_set_text_color(s_title_layer, PBL_IF_COLOR_ELSE(GColorWhite, GColorBlack));
  text_layer_set_background_color(s_title_layer, GColorClear);
  text_layer_set_text_alignment(s_title_layer, GTextAlignmentCenter);
  text_layer_set_font(s_title_layer, fonts_get_system_font(FONT_KEY_GOTHIC_24_BOLD));
  layer_add_child(window_layer, text_layer_get_layer(s_title_layer));

  const GEdgeInsets body_insets = {.top = 125, .right = 5, .left = 5};
  s_body_layer = text_layer_create(grect_inset(bounds, body_insets));
  text_layer_set_text(s_body_layer, DIALOG_CONFIG_WINDOW_MESSAGE);
  text_layer_set_text_color(s_body_layer, PBL_IF_COLOR_ELSE(GColorWhite, GColorBlack));
  text_layer_set_background_color(s_body_layer, GColorClear);
  text_layer_set_font(s_body_layer, fonts_get_system_font(FONT_KEY_GOTHIC_18_BOLD));
  text_layer_set_text_alignment(s_body_layer, GTextAlignmentCenter);
  layer_add_child(window_layer, text_layer_get_layer(s_body_layer));
}

static void window_unload(Window *window)
{
  text_layer_destroy(s_title_layer);
  text_layer_destroy(s_body_layer);

  bitmap_layer_destroy(s_icon_layer);
  gbitmap_destroy(s_icon_bitmap);

  window_destroy(window);
  s_main_window = NULL;
}

void dialog_config_window_push()
{
  if (!s_main_window)
  {
    s_main_window = window_create();
    window_set_background_color(s_main_window, PBL_IF_COLOR_ELSE(GColorDarkGray, GColorWhite));
    window_set_window_handlers(s_main_window, (WindowHandlers){
                                                  .load = window_load,
                                                  .unload = window_unload});
  }
  window_stack_push(s_main_window, true);
}

static void appmessage_inbox_received(DictionaryIterator *iter, void *context)
{
    Tuple *close_tuple = dict_find(iter, MESSAGE_KEY_Close);
    if (close_tuple) {
        APP_LOG(APP_LOG_LEVEL_DEBUG, "Received close message, closing app");
        window_stack_pop_all(true);
        return;
    }
}

static void appmessage_init(void)
{
  app_message_register_inbox_received(appmessage_inbox_received);
  app_message_open(64, 64);
  APP_LOG(APP_LOG_LEVEL_DEBUG, "AppMessage initialized");
}

static void prv_deinit(void) 
{
  if (s_main_window) {
    window_destroy(s_main_window);
    s_main_window = NULL;
  }
}

static void prv_init(void) 
{
  dialog_config_window_push();
}

int main(void)
{
  prv_init();
  appmessage_init();

  APP_LOG(APP_LOG_LEVEL_DEBUG, "Done initializing");

  app_event_loop();
  prv_deinit();
}
