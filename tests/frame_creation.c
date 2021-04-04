#include <tinyws.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./TEST.h"

static char const data[12] = "Hello World!";
static char const mask[4] = "1234";

static size_t const expected_size = 2 + sizeof(mask) + sizeof(data);
static char const expected_result[2 + sizeof(mask) + sizeof(data)] = "\x81""\x8c""1234yW_X^""\x12""d[C^W""\x15";

DEF_TEST(frame_creation)
{
    size_t frame_size;
    tinyws_make_frame(TINYWS_TEXT, mask, NULL, &frame_size, data, sizeof(data));
    EXPECTED_EQ(frame_size, expected_size);

    char* frame_buf = calloc(1, frame_size + 1);
    tinyws_make_frame(TINYWS_TEXT, mask, frame_buf, &frame_size, data, sizeof(data));
    EXPECTED_BYTES_EQ(frame_buf, expected_result, frame_size);

    free(frame_buf);
    SUCCESS();
}

int main()
{
    BEGIN_TESTING;
    TEST(frame_creation);
    END_TESTING;
}
