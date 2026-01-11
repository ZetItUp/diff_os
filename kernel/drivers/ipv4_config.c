#include "drivers/ipv4_config.h"
#include "diff.h"
#include "heap.h"
#include "stdio.h"
#include "string.h"

#define IPV4_DEFAULT_MTU 1500 // Default MTU
#define IPV4_DEFAULT_TTL 64 // Default TTL

static ipv4_config_t g_ipv4_config;
static int g_ipv4_config_loaded = 0;

// Trim left space
static void trim_left(char *text)
{
    char *cursor;

    if (!text)
    {
        return;
    }

    cursor = text;

    while (*cursor == ' ' || *cursor == '\t')
    {
        cursor++;
    }

    if (cursor != text)
    {
        memmove(text, cursor, strlen(cursor) + 1);
    }
}

// Trim right space
static void trim_right(char *text)
{
    size_t length;

    if (!text)
    {
        return;
    }

    length = strlen(text);

    while (length > 0)
    {
        char character = text[length - 1];

        if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
        {
            break;
        }

        text[length - 1] = '\0';
        length--;
    }
}

// Strip comments
static void strip_comment(char *text)
{
    char *cursor;

    if (!text)
    {
        return;
    }

    cursor = text;

    while (*cursor)
    {
        if (*cursor == '#')
        {
            *cursor = '\0';
            break;
        }

        cursor++;
    }

    trim_right(text);
}

// Get next line
static char *next_line(char **cursor)
{
    char *line;
    char *end;

    if (!cursor || !*cursor)
    {
        return NULL;
    }

    if (**cursor == '\0')
    {
        return NULL;
    }

    line = *cursor;
    end = line;

    while (*end && *end != '\r' && *end != '\n')
    {
        end++;
    }

    if (*end)
    {
        *end = '\0';
        end++;

        while (*end == '\r' || *end == '\n')
        {
            end++;
        }
    }

    *cursor = end;

    strip_comment(line);
    trim_left(line);
    trim_right(line);

    return line;
}

// Case insensitive compare
static int strings_equal_ci(const char *left, const char *right)
{
    if (!left || !right)
    {
        return 0;
    }

    while (*left && *right)
    {
        char left_char = *left;
        char right_char = *right;

        if (left_char >= 'A' && left_char <= 'Z')
        {
            left_char = (char)(left_char - 'A' + 'a');
        }

        if (right_char >= 'A' && right_char <= 'Z')
        {
            right_char = (char)(right_char - 'A' + 'a');
        }

        if (left_char != right_char)
        {
            return 0;
        }

        left++;
        right++;
    }

    return *left == '\0' && *right == '\0';
}

// Split key and value
static int split_key_value(char *line, char **key_out, char **value_out)
{
    char *equals;

    if (!line || !key_out || !value_out)
    {
        return 0;
    }

    equals = NULL;

    for (char *cursor = line; *cursor; cursor++)
    {
        if (*cursor == '=')
        {
            equals = cursor;
            break;
        }
    }

    if (!equals)
    {
        return 0;
    }

    *equals = '\0';

    *key_out = line;
    *value_out = equals + 1;

    trim_left(*key_out);
    trim_right(*key_out);
    trim_left(*value_out);
    trim_right(*value_out);

    if (**key_out == '\0' || **value_out == '\0')
    {
        return 0;
    }

    return 1;
}

// Parse unsigned integer
static int parse_uint32(const char *text, uint32_t *value_out)
{
    const char *cursor;
    uint32_t value;
    int has_digit;

    if (!text || !value_out)
    {
        return 0;
    }

    cursor = text;
    value = 0;
    has_digit = 0;

    while (*cursor)
    {
        if (*cursor < '0' || *cursor > '9')
        {
            return 0;
        }

        has_digit = 1;
        value = value * 10 + (uint32_t)(*cursor - '0');
        cursor++;
    }

    if (!has_digit)
    {
        return 0;
    }

    *value_out = value;

    return 1;
}

// Parse IPv4 address
static int parse_ipv4_address(const char *text, uint8_t output[4])
{
    uint32_t octet_value;
    int octet_index;
    int has_digit;

    if (!text || !output)
    {
        return 0;
    }

    octet_value = 0;
    octet_index = 0;
    has_digit = 0;

    for (const char *cursor = text; *cursor; cursor++)
    {
        if (*cursor >= '0' && *cursor <= '9')
        {
            has_digit = 1;
            octet_value = octet_value * 10 + (uint32_t)(*cursor - '0');

            if (octet_value > 255)
            {
                return 0;
            }

            continue;
        }

        if (*cursor == '.')
        {
            if (!has_digit || octet_index >= 3)
            {
                return 0;
            }

            output[octet_index] = (uint8_t)octet_value;
            octet_index++;
            octet_value = 0;
            has_digit = 0;

            continue;
        }

        return 0;
    }

    if (!has_digit || octet_index != 3)
    {
        return 0;
    }

    output[octet_index] = (uint8_t)octet_value;

    return 1;
}

// Set defaults
static void ipv4_config_set_defaults(ipv4_config_t *config)
{
    if (!config)
    {
        return;
    }

    memset(config, 0, sizeof(*config));

    config->use_dhcp = 0;
    config->mtu = IPV4_DEFAULT_MTU;
    config->default_ttl = IPV4_DEFAULT_TTL;
    config->valid = 0;
}

int ipv4_config_load(const FileTable *table, const char *path)
{
    const FileEntry *file_entry;
    char *file_data;
    int bytes_read;
    char *cursor;
    char *line;
    int index;

    ipv4_config_set_defaults(&g_ipv4_config);
    g_ipv4_config_loaded = 0;

    if (!table || !path)
    {
        return -1;
    }

    index = find_entry_by_path(table, path);

    if (index == -1)
    {
        printf("[IPV4] Config file '%s' not found\n", path);

        return -1;
    }

    file_entry = &table->entries[index];
    file_data = (char *)kmalloc(fe_sector_count(file_entry) * 512 + 1);

    if (!file_data)
    {
        printf("[IPV4] Out of memory reading '%s'\n", path);

        return -1;
    }

    bytes_read = read_file(table, path, file_data);

    if (bytes_read <= 0)
    {
        printf("[IPV4] Config file '%s' is empty\n", path);
        kfree(file_data);

        return -1;
    }

    file_data[bytes_read] = '\0';

    cursor = file_data;

    for (line = next_line(&cursor); line; line = next_line(&cursor))
    {
        char *key;
        char *value;

        if (*line == '\0')
        {
            continue;
        }

        if (!split_key_value(line, &key, &value))
        {
            continue;
        }

        if (strings_equal_ci(key, "device"))
        {
            strlcpy(g_ipv4_config.device_name, value, sizeof(g_ipv4_config.device_name));

            continue;
        }

        if (strings_equal_ci(key, "mode"))
        {
            if (strings_equal_ci(value, "dhcp"))
            {
                g_ipv4_config.use_dhcp = 1;
            }
            else if (strings_equal_ci(value, "static"))
            {
                g_ipv4_config.use_dhcp = 0;
            }

            continue;
        }

        if (strings_equal_ci(key, "ip"))
        {
            parse_ipv4_address(value, g_ipv4_config.ip_address);

            continue;
        }

        if (strings_equal_ci(key, "netmask"))
        {
            parse_ipv4_address(value, g_ipv4_config.netmask);

            continue;
        }

        if (strings_equal_ci(key, "gateway"))
        {
            parse_ipv4_address(value, g_ipv4_config.gateway);

            continue;
        }

        if (strings_equal_ci(key, "primary-dns"))
        {
            parse_ipv4_address(value, g_ipv4_config.primary_dns);

            continue;
        }

        if (strings_equal_ci(key, "secondary-dns"))
        {
            parse_ipv4_address(value, g_ipv4_config.secondary_dns);

            continue;
        }

        if (strings_equal_ci(key, "mtu"))
        {
            uint32_t value_number;

            if (parse_uint32(value, &value_number) && value_number > 0 && value_number <= 65535)
            {
                g_ipv4_config.mtu = (uint16_t)value_number;
            }

            continue;
        }

        if (strings_equal_ci(key, "ttl"))
        {
            uint32_t value_number;

            if (parse_uint32(value, &value_number))
            {
                if (value_number > 255)
                {
                    g_ipv4_config.mtu = (uint16_t)value_number;
                }
                else if (value_number > 0)
                {
                    g_ipv4_config.default_ttl = (uint8_t)value_number;
                }
            }

            continue;
        }
    }

    kfree(file_data);

    g_ipv4_config.valid = 1;
    g_ipv4_config_loaded = 1;

    return 0;
}

int ipv4_get_config(ipv4_config_t *out)
{
    if (!out)
    {
        return -1;
    }

    *out = g_ipv4_config;

    if (!g_ipv4_config_loaded)
    {
        return -1;
    }

    return 0;
}
