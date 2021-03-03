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

    s_frame_mask_0, // byte 11, if MASK
    s_frame_mask_1, // byte 12, if MASK
    s_frame_mask_2, // byte 13, if MASK
    s_frame_mask_3, // byte 14, if MASK

    s_payload_data,
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
static size_t tinyws_base64_encode(char const* bytes, size_t len, char* out)
{
    size_t const out_len = ((4 * len / 3) + 3) & ~3; // + 1 for the NUL terminator
    if (out != NULL) {
        int evp_len = EVP_EncodeBlock(out, bytes, len);
        if (evp_len <= 0)
            return 0;
        assert(out_len == evp_len);
    }
    return out_len + 1;
}

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

int tinyws_init(tinyws* parser, enum tinyws_type type)
{
    memset(parser, 0, sizeof(*parser));
    parser->type = type;
    return 1;
}

int tinyws_settings_init(tinyws_settings* settings)
{
    memset(settings, 0, sizeof(*settings));
    return 1;
}

size_t tinyws_execute(tinyws* parser, const tinyws_settings* settings, const char* data, size_t len)
{
    parser->ws_errno = WSE_OK;
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

    if (parser->state == s_dead)
        return 0;

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
            CONSUME_BYTE();
            parser->fin = byte & 0b10000000 ? 1 : 0;
            parser->rsv1 = byte & 0b01000000 ? 1 : 0;
            parser->rsv2 = byte & 0b00100000 ? 1 : 0;
            parser->rsv3 = byte & 0b00010000 ? 1 : 0;
            parser->opcode = byte & 0b00001111;
            parser->state = s_frame_payload_length;
        } break;

        case s_frame_payload_length: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->masked = byte & 0b10000000 ? 1 : 0;
            if (parser->type == WS_CLIENT && parser->masked)
                SET_ERRNO(WSE_UNEXPECTED_MASK_BIT);
            else if (parser->type == WS_SERVER && !parser->masked)
                SET_ERRNO(WSE_EXPECTED_MASK_BIT);

            unsigned const payload_len = byte & 0b01111111;
            if (payload_len == 126) {
                parser->state = s_frame_payload_length_16_0;
            } else if (payload_len == 127) {
                parser->state = s_frame_payload_length_64_0;
            } else {
                parser->payload_length = payload_len;
                if (parser->masked) {
                    parser->state = s_frame_mask_0;
                } else {
                    parser->nread = 0;
                    parser->state = s_payload_data;
                }
            }

        } break;

        case s_frame_payload_length_16_0: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length = byte;
            parser->state = s_frame_payload_length_16_1;
        } break;
        case s_frame_payload_length_16_1: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 1);
            parser->state = s_frame_payload_length_16_2;
        } break;
        case s_frame_payload_length_16_2: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 2);
            parser->state = s_frame_payload_length_16_3;
        } break;
        case s_frame_payload_length_16_3: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 3);
            if (parser->masked)
                parser->state = s_frame_mask_0;
            else
                parser->state = s_payload_data;
        } break;

        case s_frame_payload_length_64_0: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length = byte;
            parser->state = s_frame_payload_length_64_1;
        } break;
        case s_frame_payload_length_64_1: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 1);
            parser->state = s_frame_payload_length_64_2;
        } break;
        case s_frame_payload_length_64_2: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 2);
            parser->state = s_frame_payload_length_64_3;
        } break;
        case s_frame_payload_length_64_3: {
            REQUIRES_BYTE();
            unsigned char const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 3);
            parser->state = s_frame_payload_length_64_4;
        } break;
        case s_frame_payload_length_64_4: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 4);
            parser->state = s_frame_payload_length_64_5;
        } break;
        case s_frame_payload_length_64_5: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 5);
            parser->state = s_frame_payload_length_64_6;
        } break;
        case s_frame_payload_length_64_6: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 6);
            parser->state = s_frame_payload_length_64_7;
        } break;
        case s_frame_payload_length_64_7: {
            REQUIRES_BYTE();
            unsigned long long const byte = *data;
            CONSUME_BYTE();
            parser->payload_length &= byte << (8 * 7);
            if (parser->masked)
                parser->state = s_frame_mask_0;
            else
                parser->state = s_payload_data;
        } break;

        case s_frame_mask_0: {
            REQUIRES_BYTE();
            parser->mask[0] = *data;
            CONSUME_BYTE();
            parser->state = s_frame_mask_1;
        } break;
        case s_frame_mask_1: {
            REQUIRES_BYTE();
            parser->mask[1] = *data;
            CONSUME_BYTE();
            parser->state = s_frame_mask_2;
        } break;
        case s_frame_mask_2: {
            REQUIRES_BYTE();
            parser->mask[2] = *data;
            CONSUME_BYTE();
            parser->state = s_frame_mask_3;
        } break;
        case s_frame_mask_3: {
            REQUIRES_BYTE();
            parser->mask[3] = *data;
            CONSUME_BYTE();
            parser->state = s_payload_data;
        } break;

        case s_payload_data: {

            if (parser->nread == 0 && settings->on_frame)
                if (settings->on_frame(parser) != 0)
                    SET_ERRNO(WSE_CB_frame);
            if (parser->payload_length != 0) {
                parser->state = s_initial;
            } else {
                REQUIRES_BYTE();
                unsigned long long const remaining_bytes = parser->payload_length - parser->nread;
                unsigned long long const bytes_to_process = remaining_bytes < len ? remaining_bytes : len;
                if (settings->on_payload)
                    if (settings->on_payload(parser, data, bytes_to_process) != 0)
                        SET_ERRNO(WSE_CB_payload);
                parser->nread += bytes_to_process;
                if (parser->payload_length == parser->nread)
                    parser->state = s_initial;
                CONSUME_N_BYTES(bytes_to_process);
            }
        } break;
        }
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
