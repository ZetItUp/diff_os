#include <diffwm/damage.h>

void window_damage(window_t *window, int x_position, int y_position, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return;
    }

    if (!window->damage_pending)
    {
        window->damage_pending = 1;
        window->damage_x_position = x_position;
        window->damage_y_position = y_position;
        window->damage_width = width;
        window->damage_height = height;
        return;
    }

    int current_x_position_start = window->damage_x_position;
    int current_y_position_start = window->damage_y_position;
    int current_x_position_end = current_x_position_start + window->damage_width;
    int current_y_position_end = current_y_position_start + window->damage_height;

    int incoming_x_position_start = x_position;
    int incoming_y_position_start = y_position;
    int incoming_x_position_end = incoming_x_position_start + width;
    int incoming_y_position_end = incoming_y_position_start + height;

    if (incoming_x_position_start < current_x_position_start) current_x_position_start = incoming_x_position_start;
    if (incoming_y_position_start < current_y_position_start) current_y_position_start = incoming_y_position_start;
    if (incoming_x_position_end > current_x_position_end) current_x_position_end = incoming_x_position_end;
    if (incoming_y_position_end > current_y_position_end) current_y_position_end = incoming_y_position_end;

    window->damage_x_position = current_x_position_start;
    window->damage_y_position = current_y_position_start;
    window->damage_width = current_x_position_end - current_x_position_start;
    window->damage_height = current_y_position_end - current_y_position_start;
}
