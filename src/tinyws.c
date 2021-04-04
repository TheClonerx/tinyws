#include <tinyws.h>

#include <openssl/evp.h>

#include <assert.h>
#include <string.h>

#define SHA1_DIGEST_LENGTH 20

enum state {
    s_initial = 0,
    s_dead = 1, // unrecoverable  error
    s_frame_opcode, // FIN, RSV1-3 & opcode
    s_frame_payload_length, // MASK & payload length
    s_frame_payload_length_16_0, // if payload length == 126
    s_frame_payload_length_16_1, // if payload length == 126
    s_frame_payload_length_16_2, // if payload length == 126
    s_frame_payload_length_16_3, // if payload length == 126

    s_frame_payload_length_64_0, // if payload length == 127
    s_frame_payload_length_64_1, // if payload length == 127
    s_frame_payload_length_64_2, // if payload length == 127
    s_frame_payload_length_64_3, // if payload length == 127
    s_frame_payload_length_64_4, // if payload length == 127
    s_frame_payload_length_64_5, // if payload length == 127
    s_frame_payload_length_64_6, // if payload length == 127
    s_frame_payload_length_64_7, // if payload length == 127

    s_frame_mask_0, // if MASK
    s_frame_mask_1, // if MASK
    s_frame_mask_2, // if MASK
    s_frame_mask_3, // if MASK

    s_payload_data,

    s_text_data,
    s_binary_data,
    s_ping_data,
    s_pong_data,
    s_close_data,
};

static char const websocket_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* Currently using OpenSSL for SHA1. */
/* Hopefully we can do it ourselves one day to avoid */
/* having OpenSSL as a dependecy and maybe make it public */

typedef struct tinyws_sha1 tinyws_sha1;
struct tinyws_sha1 {
    EVP_MD_CTX* state_ptr;
};

// Initializes the SHA1 context
// returns non-zero on success
// returns zero on error
static int tinyws_sha1_init(tinyws_sha1* state)
{
    state->state_ptr = EVP_MD_CTX_new();
    if (state->state_ptr == NULL)
        return 0;
    return EVP_DigestInit(state->state_ptr, EVP_sha1()) != 0;
}

// returns non-zero on success
// returns zero on error
static int tinyws_sha1_update(tinyws_sha1* state, void const* data, size_t len)
{
    return EVP_DigestUpdate(state->state_ptr, data, len) != 0;
}

// Extracts the final digest value
// `digest` must point to a buffer of size `SHA1_DIGEST_LENGTH` or greater
// returns non-zero on success
// returns zero on error
static int tinyws_sha1_final(tinyws_sha1* state, void* digest)
{
    if (EVP_DigestFinal_ex(state->state_ptr, digest, NULL) == 0)
        return 0;
    EVP_MD_CTX_free(state->state_ptr);
    return 1;
}

/* Currently using OpenSSL for Base64. */
/* Hopefully we can do it ourselves one day to avoid */
/* having OpenSSL as a dependecy and maybe make it public */

// if `out` is NULL, we just calculate the length and return it
// if an error occur for some reason, 0 is returned
// otherwise, returns the length, including the NUL terminator
static size_t tinyws_base64_encode(void const* bytes, size_t len, void* out)
{
    size_t const out_len = ((4 * len / 3) + 3) & ~3; // + 1 for the NUL terminator
    if (out != NULL) {
        int evp_len = EVP_EncodeBlock(out, bytes, len);
        if (evp_len <= 0)
            return 0;
        assert(out_len == (unsigned)evp_len);
    }
    return out_len + 1;
}

void tinyws_mask_bytes(void const* mask, void const* data, void* out, size_t len)
{
    unsigned char const* mask_bytes = (unsigned char const*)mask;
    unsigned char const* data_bytes = (unsigned char const*)data;
    unsigned char* out_bytes = (unsigned char*)out;

    size_t const allignment_l = (size_t)out & 15;
    size_t const allignment_r = (size_t)data & 15;

    if (allignment_l != 0 || allignment_r != 0) {
        for (size_t i = 0; i < len; ++i)
            out_bytes[i] = data_bytes[i] ^ mask_bytes[i % 4];
        return;
    }

    size_t const _hem = len % 4;

    for (size_t i = 0; i < len - _hem; i += 4) {
        out_bytes[i + 0] = data_bytes[i + 0] ^ mask_bytes[0];
        out_bytes[i + 1] = data_bytes[i + 1] ^ mask_bytes[1];
        out_bytes[i + 2] = data_bytes[i + 2] ^ mask_bytes[2];
        out_bytes[i + 3] = data_bytes[i + 3] ^ mask_bytes[3];
    }

    for (size_t i = len - _hem; i < _hem; ++i)
        out_bytes[i] = data_bytes[i] ^ mask_bytes[i % 4];
}

#if TINYWS_MASK_BYTES_SSE2 == 1
/* TODO: Others compilers might require you to include a different header */
/* This has only been tested for gcc and clang */
#include <emmintrin.h>

void tinyws_mask_bytes_sse2(void const* mask, void const* data, void* out, size_t len)
{
    int32_t mask_i32;
    memcpy(&mask_i32, mask, 4);

    unsigned char* mask_bytes = (unsigned char*)mask;
    unsigned char const* data_bytes = (unsigned char const*)data;
    unsigned char* out_bytes = (unsigned char*)out;

    __m128i mask_simd = _mm_set1_epi32(mask_i32);
    __m128i data_simd;

    for (size_t i = 0; i != len;) {
        size_t const diff = len - i;
        if (diff >= 32) {
            data_simd = _mm_loadu_si128((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si128((__m128i*)out_bytes, data_simd);
            i += 16;
            data_bytes += 16;
            out_bytes += 16;
            data_simd = _mm_loadu_si128((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si128((__m128i*)out_bytes, data_simd);
            i += 16;
            data_bytes += 16;
            out_bytes += 16;
        } else if (diff >= 16) {
            data_simd = _mm_loadu_si128((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si128((__m128i*)out_bytes, data_simd);
            i += 16;
            data_bytes += 16;
            out_bytes += 16;
        } else if (diff >= 8) {
            data_simd = _mm_loadu_si64((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si64((__m128i*)out_bytes, data_simd);
            i += 8;
            data_bytes += 8;
            out_bytes += 8;
        } else if (diff >= 4) {
            data_simd = _mm_loadu_si32((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si32((__m128i*)out_bytes, data_simd);
            i += 4;
            data_bytes += 4;
            out_bytes += 4;
        } else if (diff == 3) {
            data_simd = _mm_loadu_si16((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si16((__m128i*)out_bytes, data_simd);
            out_bytes[2] = data_bytes[2] ^ mask_bytes[2];
            i += 3;
        } else if (diff == 2) {
            data_simd = _mm_loadu_si16((__m128i*)data_bytes);
            data_simd = _mm_xor_si128(data_simd, mask_simd);
            _mm_storeu_si16((__m128i*)out_bytes, data_simd);
            i += 2;
        } else {
            out_bytes[0] = data_bytes[0] ^ mask_bytes[0];
            ++i;
        }
    }
}
#endif

int tinyws_generate_accept_hash(char const* websocket_key, char* hash_out)
{
    char sha1_digest[SHA1_DIGEST_LENGTH];

    tinyws_sha1 sha1;
    if (!tinyws_sha1_init(&sha1))
        return 0;
    if (!tinyws_sha1_update(&sha1, websocket_key, strlen(websocket_key)))
        return 0;
    if (!tinyws_sha1_update(&sha1, websocket_guid, strlen(websocket_guid)))
        return 0;
    if (!tinyws_sha1_final(&sha1, sha1_digest))
        return 0;

    char b64_encoded[TINYWS_ACCEPT_HASH_MAX_LENGTH];
    size_t len = tinyws_base64_encode(sha1_digest, SHA1_DIGEST_LENGTH, b64_encoded);
    if (!len)
        return 0;

    memcpy(hash_out, b64_encoded, len);
    return len;
}

TINYWS_BOOL tinyws_make_frame(enum tinyws_opcode opcode, void const* mask, void* frame_out, size_t* frame_out_size, void const* data, size_t data_size)
{
    // One byte for FIN, RSV1-3 and OPCODE bits
    // One byte for MASK and payload len
    size_t bytes_needed = 2;
    size_t start_payload;

    if (data) {
        if (opcode == TINYWS_CLOSE) {
            if (data_size < 2)
                return TINYWS_FALSE;
            bytes_needed += 2;
        }

        if (mask)
            bytes_needed += 4;
        if (data_size > UINT16_MAX)
            bytes_needed += 8;
        else if (data_size > 125)
            bytes_needed += 2;

        // Check if we can fit the frame in size_t
        // `SIZE_MAX - data_size` is the number of bytes left
        if (SIZE_MAX - data_size < bytes_needed)
            return TINYWS_FALSE;

        start_payload = bytes_needed;
        bytes_needed += data_size;
    }

    if (!frame_out) {
        *frame_out_size = bytes_needed;
        return TINYWS_TRUE;
    }

    if (*frame_out_size < bytes_needed)
        return TINYWS_FALSE;

    unsigned char bytes[2 + 8 + 4];
    bytes[0] = 0b10000000 | opcode;
    bytes[1] = 0b10000000 * (mask != NULL);
    if (data_size > UINT16_MAX) {
        bytes[1] |= 127;
        bytes[2] = (data_size >> 0) & 0xFF;
        bytes[3] = (data_size >> 8) & 0xFF;
        bytes[4] = (data_size >> 16) & 0xFF;
        bytes[5] = (data_size >> 24) & 0xFF;
        bytes[6] = (data_size >> 32) & 0xFF;
        bytes[7] = (data_size >> 40) & 0xFF;
        bytes[8] = (data_size >> 48) & 0xFF;
        bytes[9] = (data_size >> 56) & 0xFF;
        if (mask) {
            bytes[10] = ((unsigned char const*)mask)[0];
            bytes[11] = ((unsigned char const*)mask)[1];
            bytes[12] = ((unsigned char const*)mask)[2];
            bytes[13] = ((unsigned char const*)mask)[3];
        }

    } else if (data_size > 125) {
        bytes[1] |= 126;
        bytes[2] = (data_size >> 0) & 0xFF;
        bytes[3] = (data_size >> 8) & 0xFF;
        if (mask) {
            bytes[4] = ((unsigned char const*)mask)[0];
            bytes[5] = ((unsigned char const*)mask)[1];
            bytes[6] = ((unsigned char const*)mask)[2];
            bytes[7] = ((unsigned char const*)mask)[3];
        }
    } else {
        bytes[1] |= data_size;
        if (mask) {
            bytes[2] = ((unsigned char const*)mask)[0];
            bytes[3] = ((unsigned char const*)mask)[1];
            bytes[4] = ((unsigned char const*)mask)[2];
            bytes[5] = ((unsigned char const*)mask)[3];
        }
    }

    memcpy(frame_out, bytes, start_payload);

    if (mask) {
#ifdef TINYWS_MASK_BYTES_SSE2
        tinyws_mask_bytes_sse2(mask, data, (char*)frame_out + start_payload, data_size);
#else
        tinyws_mask_bytes(mask, data, (char*)frame_out + start_payload, data_size);
#endif
    } else {
        memcpy((char*)frame_out + start_payload, data, data_size);
    }

    return TINYWS_TRUE;
}

TINYWS_BOOL tinyws_init(tinyws* parser, enum tinyws_type type)
{
    memset(parser, 0, sizeof(*parser));
    parser->type = type;
    return TINYWS_TRUE;
}

TINYWS_BOOL tinyws_settings_init(tinyws_settings* settings)
{
    memset(settings, 0, sizeof(*settings));
    return TINYWS_TRUE;
}

size_t tinyws_execute(tinyws* parser, const tinyws_settings* settings, const char* data, size_t len)
{
    size_t nread = 0;

#define CONSUME_BYTE() \
    do {               \
        ++data;        \
        --len;         \
        ++nread;       \
    } while (0)

#define CONSUME_N_BYTES(n) \
    do {                   \
        data += n;         \
        len -= n;          \
        nread += n;        \
    } while (0)

#define REQUIRES_BYTE()   \
    do {                  \
        if (len == 0)     \
            return nread; \
    } while (0)

#define REQUIRES_N_BYTES(n) \
    do {                    \
        if (n > len)        \
            return nread;   \
    } while (0)

#define SET_ERRNO(n)          \
    do {                      \
        parser->ws_errno = n; \
        return nread;         \
    } while (0)

#define SET_UNRECOVERABLE_ERRNO(n) \
    do {                           \
        parser->ws_errno = n;      \
        parser->state = s_dead;    \
        return nread;              \
    } while (0)

#define CALLBACK(name)                                            \
    do {                                                          \
        if (settings->on_##name) {                                \
            if ((parser->cb_errno = settings->on_##name(parser))) \
                SET_ERRNO(WSE_CB_##name);                         \
        }                                                         \
    } while (0)

#define CALLBACK_DATA(name, d, l)                                           \
    do {                                                                    \
        if (settings->on_##name) {                                          \
            if ((parser->cb_errno = settings->on_##name(parser, (d), (l)))) \
                SET_ERRNO(WSE_CB_##name);                                   \
        }                                                                   \
    } while (0)

#define CHANGE_STATE(new_state)        \
    do {                               \
        parser->state = s_##new_state; \
        goto end_loop;                 \
    } while (0)

#define CONTROL_BIT (0b1000u)

    if (parser->state == s_dead)
        return 0;

    parser->ws_errno = WSE_OK;

    if (len == 0) { // eof
        switch (parser->type) {
        case s_initial:
            return 0;

        default:
            SET_ERRNO(WSE_INVALID_EOF_STATE);
        }
    }

    for (;;) {
        switch (parser->state) {
        case s_initial: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            parser->fin = byte & 0b10000000 ? 1 : 0;
            parser->rsv1 = byte & 0b01000000 ? 1 : 0;
            parser->rsv2 = byte & 0b00100000 ? 1 : 0;
            parser->rsv3 = byte & 0b00010000 ? 1 : 0;
            parser->opcode = byte & 0b00001111;
            if (parser->opcode & CONTROL_BIT && !parser->fin)
                SET_ERRNO(WSE_EXPECTED_FIN_BIT);
            CONSUME_BYTE();
            CHANGE_STATE(frame_payload_length);
        }
        case s_frame_payload_length: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            parser->masked = byte & 0b10000000 ? 1 : 0;
            if (parser->type == WS_CLIENT && parser->masked)
                SET_ERRNO(WSE_UNEXPECTED_MASK_BIT);
            else if (parser->type == WS_SERVER && !parser->masked)
                SET_ERRNO(WSE_EXPECTED_MASK_BIT);
            CONSUME_BYTE();

            unsigned const payload_len = byte & 0b01111111;
            if (payload_len == 126) {
                CHANGE_STATE(frame_payload_length_16_0);
            } else if (payload_len == 127) {
                CHANGE_STATE(frame_payload_length_64_0);
            } else {
                parser->payload_length = payload_len;
                if (parser->masked) {
                    CHANGE_STATE(frame_mask_0);
                } else {
                    parser->nread = 0;
                    CHANGE_STATE(payload_data);
                }
            }
        }
        case s_frame_payload_length_16_0: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length = byte;
            CHANGE_STATE(frame_payload_length_16_1);
        }
        case s_frame_payload_length_16_1: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 1);
            CHANGE_STATE(frame_payload_length_16_2);
        }
        case s_frame_payload_length_16_2: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 2);
            CHANGE_STATE(frame_payload_length_16_3);
        }
        case s_frame_payload_length_16_3: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 3);
            if (parser->masked)
                CHANGE_STATE(frame_mask_0);
            else
                CHANGE_STATE(payload_data);
        }
        case s_frame_payload_length_64_0: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length = byte;
            CHANGE_STATE(frame_payload_length_64_1);
        }
        case s_frame_payload_length_64_1: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 1);
            CHANGE_STATE(frame_payload_length_64_2);
        }
        case s_frame_payload_length_64_2: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 2);
            CHANGE_STATE(frame_payload_length_64_3);
        }
        case s_frame_payload_length_64_3: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 3);
            CHANGE_STATE(frame_payload_length_64_4);
        }
        case s_frame_payload_length_64_4: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 4);
            CHANGE_STATE(frame_payload_length_64_5);
        }
        case s_frame_payload_length_64_5: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 5);
            CHANGE_STATE(frame_payload_length_64_6);
        }
        case s_frame_payload_length_64_6: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 6);
            CHANGE_STATE(frame_payload_length_64_7);
        }
        case s_frame_payload_length_64_7: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 7);
            if (parser->masked)
                CHANGE_STATE(frame_mask_0);
            else
                CHANGE_STATE(payload_data);
        }
        case s_frame_mask_0: {
            REQUIRES_BYTE();
            parser->mask[0] = *data;
            CONSUME_BYTE();
            CHANGE_STATE(frame_mask_1);
        }
        case s_frame_mask_1: {
            REQUIRES_BYTE();
            parser->mask[1] = *data;
            CONSUME_BYTE();
            CHANGE_STATE(frame_mask_2);
        }
        case s_frame_mask_2: {
            REQUIRES_BYTE();
            parser->mask[2] = *data;
            CONSUME_BYTE();
            CHANGE_STATE(frame_mask_3);
        }
        case s_frame_mask_3: {
            REQUIRES_BYTE();
            parser->mask[3] = *data;
            CONSUME_BYTE();
            CHANGE_STATE(payload_data);
        }
        case s_payload_data: {
            if (parser->nread == 0) {
                CALLBACK(frame);

                switch (parser->opcode) {
                case TINYWS_CLOSE:
                    CALLBACK(close);
                    break;
                case TINYWS_PING:
                    CALLBACK(ping);
                    break;
                case TINYWS_PONG:
                    CALLBACK(pong);
                    break;
                default:
                    break;
                }
            }

            if (parser->payload_length != 0) {
                CHANGE_STATE(initial);
            } else {
                REQUIRES_BYTE();
                unsigned long long const remaining_bytes = parser->payload_length - parser->nread;
                unsigned long long const bytes_to_process = remaining_bytes < len ? remaining_bytes : len;
                CALLBACK_DATA(payload, data, bytes_to_process);
                parser->nread += bytes_to_process;
                if (parser->payload_length == parser->nread)
                    CHANGE_STATE(initial);
                CONSUME_N_BYTES(bytes_to_process);
            }
        }
        }
    end_loop:;
    }
    return nread;
}

/* Return a string name of the given error */
char const* tinyws_errno_name(enum tinyws_errno err)
{
#define WS_ERRNO_NAME_GEN(name, description) \
    case WSE_##name:                         \
        return "WSE_" #name;
    switch (err) {
        TINYWS_ERRNO_MAP(WS_ERRNO_NAME_GEN)

    default:
        return "unkown";
    }
#undef WS_ERRNO_NAME_GEN
}

/* Return a string description of the given error */
char const* tinyws_errno_description(enum tinyws_errno err)
{
#define WS_ERRNO_DESC_GEN(name, description) \
    case WSE_##name:                         \
        return description;
    switch (err) {
        TINYWS_ERRNO_MAP(WS_ERRNO_DESC_GEN)

    default:
        return "unkown";
    }
#undef WS_ERRNO_DESC_GEN
}
