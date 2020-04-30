#include <compress.h>
#include <lz4.h>
#include <lz4hc.h>

#include <cstring>

const size_t MESSAGE_MAX_BYTES = 1024,
             RING_BUFFER_BYTES = 1024 * 8 + MESSAGE_MAX_BYTES,
             DEC_BUFFER_BYTES =
                 RING_BUFFER_BYTES +
                 MESSAGE_MAX_BYTES;  // Intentionally larger to test
                                     // unsynchronized ring buffers

//------------------------------------------------------------------------------
std::string compress(const char* buff, size_t n) {
    LZ4_streamHC_t lz4Stream_body = {0};
    LZ4_streamHC_t* lz4Stream = &lz4Stream_body;
    static char ringbuff[RING_BUFFER_BYTES];
    int ring_off = 0;
    size_t in_off = 0;
    std::string ret;
int i =0;
    for (;;) {++i;
        char* const inpPtr = &ringbuff[ring_off];
        const int inpBytes = std::min(n - in_off, MESSAGE_MAX_BYTES);
        memcpy(inpPtr, buff+in_off, inpBytes);
        in_off += inpBytes;
        if (0 == inpBytes) { break; }

#define CMPBUFSIZE (LZ4_COMPRESSBOUND(MESSAGE_MAX_BYTES))
        {
            char cmpBuf[CMPBUFSIZE];
            const int32_t cmpBytes = LZ4_compress_HC_continue(
                lz4Stream, inpPtr, cmpBuf, inpBytes, CMPBUFSIZE);

            if (cmpBytes <= 0) break;
            ret += std::string((char*)&cmpBytes, sizeof(cmpBytes)) +
                   std::string(cmpBuf, cmpBytes);

            ring_off += inpBytes;

            // Wraparound the ringbuffer offset
            if (ring_off >= RING_BUFFER_BYTES - MESSAGE_MAX_BYTES) ring_off = 0;
        }
    }
    int32_t zero = 0;
    ret += std::string((char*)&zero, sizeof(zero));
    return ret;
}

//------------------------------------------------------------------------------
std::string decompress(const char* buff, size_t n) {
    static char decBuf[DEC_BUFFER_BYTES];
    int decOffset = 0;
    LZ4_streamDecode_t lz4StreamDecode_body = {0};
    LZ4_streamDecode_t* lz4StreamDecode = &lz4StreamDecode_body;

    size_t in_off = 0;
    std::string ret;
    for (;;) {
        int32_t cmpBytes = 0;
        char cmpBuf[CMPBUFSIZE];

        {
            const size_t r0 = n - in_off >= sizeof(cmpBytes) ? 1 : 0;
            if (r0) {
                memcpy(&cmpBytes, buff + in_off, sizeof(cmpBytes));
                in_off += sizeof(cmpBytes);
            }
            size_t r1;
            if (r0 != 1 || cmpBytes <= 0) break;

            r1 = std::min((int32_t)(n - in_off), cmpBytes);
            if (r1 != 0) {
                memcpy(cmpBuf, buff + in_off, r1);
                in_off += r1;
            }
            if (r1 != (size_t)cmpBytes) break;
        }

        {
            char* const decPtr = &decBuf[decOffset];
            const int decBytes = LZ4_decompress_safe_continue(
                lz4StreamDecode, cmpBuf, decPtr, cmpBytes, MESSAGE_MAX_BYTES);
            if (decBytes <= 0) break;

            decOffset += decBytes;
            ret += std::string(decPtr, decBytes);

            // Wraparound the ringbuffer offset
            if (decOffset >= DEC_BUFFER_BYTES - MESSAGE_MAX_BYTES)
                decOffset = 0;
        }
    }
    return ret;
}
