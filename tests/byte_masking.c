#include <tinyws.h>

#include <assert.h>
#include <string.h>

static char const data_to_mask[] = "Hello World!";
static char const mask[4] = "ibrs";

#include "./TEST.h"

DEF_TEST(masking_roundtrip)
{
    char masked_data[sizeof(data_to_mask)] = {};
    tinyws_mask_bytes(mask, data_to_mask, masked_data, sizeof(data_to_mask));

    char unmasked_data[sizeof(data_to_mask)] = {};
    tinyws_mask_bytes(mask, masked_data, unmasked_data, sizeof(data_to_mask));

    EXPECTED_BYTES_EQ(data_to_mask, unmasked_data, sizeof(data_to_mask));

    SUCCESS();
}

#if TINYWS_MASK_BYTES_SSE2 == 1
DEF_TEST(masking_roundtrip_sse2)
{
    char masked_data[sizeof(data_to_mask)] = {};
    tinyws_mask_bytes_sse2(mask, data_to_mask, masked_data, sizeof(data_to_mask));

    char unmasked_data[sizeof(data_to_mask)] = {};
    tinyws_mask_bytes_sse2(mask, masked_data, unmasked_data, sizeof(data_to_mask));

    EXPECTED_BYTES_EQ(data_to_mask, unmasked_data, sizeof(data_to_mask));

    SUCCESS();
}
#endif

int main()
{
    BEGIN_TESTING;
    TEST(masking_roundtrip);

#if TINYWS_MASK_BYTES_SSE2 == 1
    TEST(masking_roundtrip_sse2);
#endif

    END_TESTING;
}