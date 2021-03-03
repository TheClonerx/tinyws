#ifndef TCX_TINYWS_H
#define TCX_TINYWS_H

#include <stddef.h>

#if !defined(TINYWS_NONNULL) && (defined(__clang__) || defined(__GNUC__)) && __has_attribute(nonnull)
#define TINYWS_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#endif

#ifndef TINYWS_NONNULL
#define TINYWS_NONNULL
#endif

#define TINYWS_ACCEPT_HASH_MAX_LENGTH 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tinyws tinyws;
typedef struct tinyws_settings tinyws_settings;
typedef struct tinyws_frame tinyws_frame;

#define TINYWS_OPCODE_MAP(XX)      \
    /* frame-opcode-cont */        \
    XX(0x0, CONTINUATION)          \
    /* frame-opcode-non-control */ \
    XX(0x1, TEXT)                  \
    XX(0x2, BINARY)                \
    XX(0x3, RESERVED_NONCONTROL_1) \
    XX(0x4, RESERVED_NONCONTROL_2) \
    XX(0x5, RESERVED_NONCONTROL_3) \
    XX(0x6, RESERVED_NONCONTROL_4) \
    XX(0x7, RESERVED_NONCONTROL_5) \
    /* frame-opcode-control */     \
    XX(0x8, CLOSE)                 \
    XX(0x9, PING)                  \
    XX(0xA, PONG)                  \
    XX(0xB, RESERVED_CONTROL_1)    \
    XX(0xC, RESERVED_CONTROL_2)    \
    XX(0xD, RESERVED_CONTROL_3)    \
    XX(0xE, RESERVED_CONTROL_4)    \
    XX(0xF, RESERVED_CONTROL_5)

enum tinyws_opcode {
#define XX(num, name) TINYWS_##name = num,
    TINYWS_OPCODE_MAP(XX)
#undef XX
};

#define TINYWS_STATUS_CODE_MAP(XX)                                            \
    /* https://tools.ietf.org/html/rfc6455#section-7.4 */                     \
                                                                              \
    /* 0-999 */                                                               \
    /*  Status codes in the range 0-999 are not used. */                      \
                                                                              \
    /* 1000-2999 */                                                           \
    /*  Status codes in the range 1000-2999 are reserved for definition by */ \
    /*  this protocol, its future revisions, and extensions specified in a */ \
    /*  permanent and readily available public specification. */              \
    XX(1000, NORMAL_CLOSURE)                                                  \
    XX(1001, GOING_AWAY)                                                      \
    XX(1002, PROTOCOL_ERROR)                                                  \
    XX(1003, UNACCEPTABLE_DATA_TYPE)                                          \
    XX(1004, RESERVED)                                                        \
    XX(1005, NO_STATUS)                                                       \
    XX(1006, CLOSED_ABNORMALLY)                                               \
    XX(1007, POLICY_VIOLATION)                                                \
    XX(1008, TOO_BIG)                                                         \
    XX(1010, EXPECTED_EXTENSION)                                              \
    XX(1011, SERVER_ERROR)                                                    \
    XX(1015, NO_TLS)                                                          \
                                                                              \
    /* 3000-3999 */                                                           \
    /*  Status codes in the range 3000-3999 are reserved for use by */        \
    /*  libraries, frameworks, and applications.  These status codes are */   \
    /*  registered directly with IANA.  The interpretation of these codes */  \
    /*  is undefined by this protocol. */                                     \
                                                                              \
    /* 4000-4999 */                                                           \
    /*  Status codes in the range 4000-4999 are reserved for private use */   \
    /*  and thus can't be registered.  Such codes can be used by prior */     \
    /*  agreements between WebSocket applications.  The interpretation of */  \
    /*  these codes is undefined by this protocol. */

enum tinyws_status_code {
#define XX(num, name) TINYWS_##name = num,
    TINYWS_STATUS_CODE_MAP(XX)
#undef XX
};

#define TINYWS_ERRNO_MAP(XX)                                    \
    /* No error */                                              \
    XX(OK, "success")                                           \
                                                                \
    /* Callback-related errors */                               \
    XX(CB_frame, "the on_frame callback failed")                \
    XX(CB_payload, "the on_payload callback failed")            \
                                                                \
    /* Parsing-related errors */                                \
    XX(INVALID_EOF_STATE, "stream ended at an unexpected time") \
    XX(UNEXPECTED_MASK_BIT, "client received a frame with the MASK bit set")

#define WS_ERRNO_GEN(n, s) WSE_##n,
enum tinyws_errno {
    TINYWS_ERRNO_MAP(WS_ERRNO_GEN)
};
#undef WS_ERRNO_GEN

enum tinyws_type {
    WS_SERVER,
    WS_CLIENT,
    WS_BOTH
};

typedef int (*tinyws_data_cb)(tinyws*, const char* at, size_t length);
typedef int (*tinyws_cb)(tinyws*);

struct tinyws_frame {
    unsigned fin : 1;
    unsigned rsv1 : 1;
    unsigned rsv2 : 1;
    unsigned rsv3 : 1;
    unsigned opcode : 4;
    unsigned mask : 1;
    unsigned payload_len : 7;
    union {
        unsigned extended_short_payload_length : 16; // if payload_len == 126
        unsigned long long extended_long_payload_length : 64; // if payload_len == 127
    };
    char masking_key[4];
};

struct tinyws {
    /** READ ONLY **/
    unsigned fin : 1;
    unsigned rsv1 : 1;
    unsigned rsv2 : 1;
    unsigned rsv3 : 1;
    unsigned opcode : 4;
    unsigned masked : 1;
    /* PRIVATE */
    unsigned type : 2;
    char mask[4];
    unsigned state;
    unsigned long long nread;
    char utf8buff[4];

    /** READ ONLY **/
    unsigned long long payload_length; // at least 63 bits
    unsigned ws_errno;

    /** PUBLIC **/
    void* data;
};

struct tinyws_settings {
    /* low level callbacks, might be useful for some websocket extensions */
    tinyws_cb on_frame; // a frame was received
    tinyws_data_cb on_payload; // payload data is being received

    tinyws_cb on_close; // a CLOSE frame was received, if it wasnt requested, you must send a CLOSE
    tinyws_cb on_ping; // a PING frame was received, you must answer with a PONG
    tinyws_cb on_pong; // a PONG frame was received

    tinyws_data_cb on_close_data; // close frame might include utf8 text
    tinyws_data_cb on_ping_data; // ping frame might include binary data
    tinyws_data_cb on_pong_data; // pong frame might include binary data

    tinyws_data_cb on_text; // utf8 text is being received
    tinyws_data_cb on_binary; // binary data might be received

    tinyws_cb on_message_complete; // text or binary messaged ended, note that you might receive CLOSE, PING or PONG in between
};

/* Generates the hash required for the Sec-Websocket-Accept header */
/* `hash_out` must point to a buffer of at least `TINYWS_ACCEPT_HASH_MAX_LENGTH` bytes */
/* returns the length of the hash, including the NUL terminator on success */
/* returns zero on error */
int tinyws_generate_accept_hash(char const* websocket_key, char* hash_out) TINYWS_NONNULL(1, 2);

/* Initializes the tinyws context, one should be used per connection */
/* returns non-zero on success */
/* returns zero on error */
int tinyws_init(tinyws* parser, enum tinyws_type type) TINYWS_NONNULL(1);

/* Initializes the tinyws context settings, one must be used per tinyws context */
/* returns non-zero on success */
/* returns zero on error */
int tinyws_settings_init(tinyws_settings* settings) TINYWS_NONNULL(1);

/* returns the amount of bytes consumed, it might be less than `len`, in which case, more data is needed */
/* returns zero on error */
size_t tinyws_execute(tinyws* parser, tinyws_settings const* settings, char const* data, size_t len) TINYWS_NONNULL(1, 2, 3);

/* Returns a string name of the given error */
char const* tinyws_errno_name(enum tinyws_errno err);

/* Returns a string description of the given error */
char const* tinyws_errno_description(enum tinyws_errno err);

#ifdef __cplusplus
}
#endif

#endif