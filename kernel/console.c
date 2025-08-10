#include "io.h"
#include "console.h"
#include "stdint.h"
#include "stdio.h"

#define SCREEN_WIDTH    80
#define SCREEN_HEIGHT   25
#define VIDEO_MEMORY    ((volatile unsigned short*)0xB8000)

static int cursor_x = 0;
static int cursor_y = 0;

static int floor_enabled = 0;
static int floor_x = 0;
static int floor_y = 0;

unsigned char current_attrib = MAKE_COLOR(FG_GRAY, BG_BLACK);

uint8_t vga_cell_height(void) 
{
    outb(0x3D4, 0x09);                 // Maximum Scan Line

    return (inb(0x3D5) & 0x1F) + 1;    // höjd i scanlines
}

void vga_cursor_enable(uint8_t start, uint8_t end) 
{
    outb(0x3D4, 0x0A);                 // Cursor Start
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, (cur & 0xC0) | (start & 0x1F));  // bit5=0 => enable

    outb(0x3D4, 0x0B);                 // Cursor End
    cur = inb(0x3D5);
    outb(0x3D5, (cur & 0xE0) | (end & 0x1F));
}

void vga_cursor_disable(void) 
{
    outb(0x3D4, 0x0A);
    uint8_t cur = inb(0x3D5);
    outb(0x3D5, cur | 0x20);           // bit5=1 => disable
}

// Print a character to the screen
void putch(char c)
{
    putch_color(current_attrib, c);
}

void set_cursor_pos(unsigned short col, unsigned short row)
{
    unsigned short pos = row * SCREEN_WIDTH + col;

    // Pick register 0x0F (cursor position low byte) via command port 0x3D4
    outb(0x3D4, 0x0F);
    // Send the low 8 bits of the position to dataport 0x3D5
    outb(0x3D5, (unsigned char)(pos & 0xFF));

    // Write high bytes (bits 8-15)
    // Pick register 0x0E (cursor position high byte) via command port 0x3D4
    outb(0x3D4, 0x0E);
    // Send the hight 8 bits of the position to data port 0x3D5
    outb(0x3D5, (unsigned char)((pos >> 8) & 0xFF));
}

unsigned short get_cursor_pos(void)
{
    unsigned short pos = 0;

    // Read low byte (bits 0 - 7) of the position

    // Pick register 0x0F (cursor position low byte)
    outb(0x3D4, 0x0F);
    // Read the low 8 bits from data port 0x3D5
    pos |= inb(0x3D5);     // Sets into bits 0-7
                              
    // Read high byte (bits 8 - 15) of the position
    
    // Pick register 0x0E (cursor position high byte)
    outb(0x3D4, 0x0E);
    // Read the high 8 bits and put them into the positions high part
    pos |= ((unsigned short)inb(0x3D5)) << 8;

    return pos;
}

void get_cursor(int *x, int *y)
{
    if(x)
    {
        *x = cursor_x;
    }

    if(y)
    {
        *y = cursor_y;
    }
}

unsigned short get_row(void)
{
    return get_cursor_pos() / SCREEN_WIDTH;
}

unsigned short get_col(void)
{
    return get_cursor_pos() % SCREEN_WIDTH;
}

static inline int at_floor(void)
{
    if(!floor_enabled)
    {
        return 0;
    }

    if(cursor_y < floor_y)
    {
        return 1;
    }

    if(cursor_y > floor_y)
    {
        return 0;
    }

    return cursor_x <= floor_x;
}

void set_input_floor(int x, int y)
{
    if(x < 0)
    {
        x = 0;
    }

    if(x >= SCREEN_WIDTH)
    {
        x = SCREEN_WIDTH - 1;
    }

    if(y < 0)
    {
        y = 0;
    }

    if(y >= SCREEN_WIDTH)
    {
        y = SCREEN_HEIGHT - 1;
    }

    floor_enabled = 1;
    floor_x = x;
    floor_y = y;
}

void clear_input_floor(void)
{
    floor_enabled = 0;
}

void putch_color(unsigned char attrib, char c)
{
    if(c == '\n')
    {
        // New line
        cursor_x = 0;
        cursor_y++;
    }
    else if(c == '\r')
    {
        // Go to the beginning of the line
        cursor_x = 0;
    }
    else if(c == '\t')
    {
        cursor_x += 4;
        set_x(cursor_x);
    }
    else if(c == '\b')
    {
        if(!at_floor() && cursor_x > 0)
        {
            cursor_x--;
            putch(' ');
            cursor_x--;            
            set_x(cursor_x);
            
            return;
        }
    }
    else
    {
        // Print the character into the buffer
        if((cursor_x >= 0 && cursor_x < SCREEN_WIDTH) &&
           (cursor_y >= 0 && cursor_y < SCREEN_HEIGHT))
        {
            VIDEO_MEMORY[cursor_x + SCREEN_WIDTH * cursor_y] = ((unsigned short)attrib << 8) | (unsigned char)c;
        }

        cursor_x++;

        // End of the line?
        if(cursor_x >= SCREEN_WIDTH)
        {
            cursor_x = 0;
            cursor_y++;      
        }
    }

    // End of the screen, scroll up
    if(cursor_y >= SCREEN_HEIGHT)
    {
        for(int y = 1; y < SCREEN_HEIGHT; y++)
        {
            for(int x = 0; x < SCREEN_WIDTH; x++)
            {
                VIDEO_MEMORY[x + SCREEN_WIDTH * (y - 1)] = VIDEO_MEMORY[x + SCREEN_WIDTH * y];
            }
        }

        // Clear the bottom row
        for(int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * (SCREEN_HEIGHT - 1)] = ((unsigned short)current_attrib << 8) | ' ';
        }

        cursor_y = SCREEN_HEIGHT - 1;
    }

    set_cursor_pos(cursor_x, cursor_y);
}

int puts(const char *str)
{
    while (*str)
    {
        putch(*str++);
    }

    return 0;
}

void set_color(unsigned char attrib)
{
    current_attrib = attrib;
}

void set_x(int x)
{
    if(x >= 0 && x < SCREEN_WIDTH)
    {
        cursor_x = x;
        set_cursor_pos(cursor_x, cursor_y);
    }
}

void set_y(int y)
{
    if(y >= 0 && y < SCREEN_HEIGHT)
    {
        cursor_y = y;
        set_cursor_pos(cursor_x, cursor_y);
    }
}

void set_pos(int x, int y)
{
    set_x(x);
    set_y(y);
}

void clear(void)
{
    for(int y = 0; y < SCREEN_HEIGHT; y++)
    {
        for(int x = 0; x < SCREEN_WIDTH; x++)
        {
            VIDEO_MEMORY[x + SCREEN_WIDTH * y] = ((unsigned short)current_attrib << 8) | ' ';
        }
    }

    set_pos(0, 0);
}

void puthex(int value)
{
    for(int i = 7; i >= 0; i--)
    {
        int nibble = (value >> (i * 4)) & 0xF;
        char hex_char = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
        putch(hex_char);
    }
}
