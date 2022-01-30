#include <cstddef>
#include <string>

#include "massip-addr.c"

extern "C"
{
void banout_end(struct BannerOutput *banout, unsigned proto);
void banout_append_unicode(struct BannerOutput *banout, unsigned proto, unsigned c);
void banout_append(struct BannerOutput *banout, unsigned proto, const void *px, size_t length);
void tcp_close(struct InteractiveData *more);
}

#include "proto-minecraft.h"
#include "proto-interactive.h"

#define MC_PROTO_MAX_PACKET_SIZE 1024

static void minecraft_parse([[maybe_unused]] const struct Banner1 *banner1,
                            [[maybe_unused]] void *banner1_private,
                            [[maybe_unused]] struct ProtocolState *pstate,
                            const unsigned char *px, size_t length,
                            struct BannerOutput *banout,
                            struct InteractiveData *more) {
    if (length > MC_PROTO_MAX_PACKET_SIZE) {
        tcp_close(more);
        return;
    }

    std::string read_data;
    for (size_t i = 0; i < length; i++) {
        read_data.append(reinterpret_cast<const char *>(&px[i]), 1);
    }

    int delim_count = 0;
    for (size_t t = 10; t < read_data.size(); t += 2) {
        char &i = read_data[t];
        if ((int) i == 0) {
            delim_count++;
        }
    }

    if (delim_count == 4 && read_data[0] == '\xFF') {
        banout_append(banout, PROTO_MINECRAFT, px, length);
    }
    banout_end(banout, PROTO_MINECRAFT);
    tcp_close(more);
}

static void *minecraft_init([[maybe_unused]] struct Banner1 *banner1) {
    return nullptr;
}

static int minecraft_selftest() {
    return 0;
}

const struct ProtocolParserStream banner_minecraft = {
    "minecraft",
    25565,
    "\xFE\x01",
    2,
    0,
    minecraft_selftest,
    minecraft_init,
    minecraft_parse,
    nullptr,
    nullptr,
    nullptr
};
