/*
 * LogForge Tier 4 Native C / NEON Probe (`native/c/logforge_neon_probe.c`)
 *
 * Pure memory-only delimiter scanners (no syscalls, no filesystem/network I/O)
 * exposing C ABI entry points for Python `ctypes` differential verification
 * and standalone ARM64 benchmark comparison against Rust `std::arch::aarch64`.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

size_t logforge_c_scalar_scan_delimiters(
    const uint8_t *data,
    size_t len,
    uint8_t delim,
    uint64_t *out_offsets,
    size_t out_cap
) {
    if (data == NULL || len == 0) {
        return 0;
    }
    if (out_offsets == NULL) {
        out_cap = 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == delim) {
            if (count < out_cap) {
                out_offsets[count] = (uint64_t)i;
            }
            ++count;
        }
    }
    return count;
}

size_t logforge_c_neon_scan_delimiters(
    const uint8_t *data,
    size_t len,
    uint8_t delim,
    uint64_t *out_offsets,
    size_t out_cap
) {
    if (data == NULL || len == 0) {
        return 0;
    }
    if (out_offsets == NULL) {
        out_cap = 0;
    }

#if defined(__aarch64__) || defined(_M_ARM64)
    static const uint8_t kBitWeights[16] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
    };
    const uint8x16_t needle = vdupq_n_u8(delim);
    const uint8x16_t weights = vld1q_u8(kBitWeights);
    size_t count = 0;
    size_t offset = 0;

    while (offset + 64 <= len) {
        uint8x16_t v0 = vld1q_u8(data + offset);
        uint8x16_t v1 = vld1q_u8(data + offset + 16);
        uint8x16_t v2 = vld1q_u8(data + offset + 32);
        uint8x16_t v3 = vld1q_u8(data + offset + 48);

        uint8x16_t eq0 = vceqq_u8(v0, needle);
        uint8x16_t eq1 = vceqq_u8(v1, needle);
        uint8x16_t eq2 = vceqq_u8(v2, needle);
        uint8x16_t eq3 = vceqq_u8(v3, needle);

        uint8x16_t m0 = vandq_u8(eq0, weights);
        uint8x16_t m1 = vandq_u8(eq1, weights);
        uint8x16_t m2 = vandq_u8(eq2, weights);
        uint8x16_t m3 = vandq_u8(eq3, weights);

        uint8x16_t p0 = vpaddq_u8(m0, m1);
        uint8x16_t p1 = vpaddq_u8(m2, m3);
        uint8x16_t p2 = vpaddq_u8(p0, p1);
        uint8x16_t p3 = vpaddq_u8(p2, p2);

        uint64_t mask = vgetq_lane_u64(vreinterpretq_u64_u8(p3), 0);
        while (mask != 0) {
            unsigned tz = (unsigned)__builtin_ctzll(mask);
            if (count < out_cap) {
                out_offsets[count] = (uint64_t)(offset + tz);
            }
            ++count;
            mask &= (mask - 1ULL);
        }
        offset += 64;
    }

    while (offset + 16 <= len) {
        uint8x16_t v = vld1q_u8(data + offset);
        uint8x16_t eq = vceqq_u8(v, needle);
        uint8x16_t masked = vandq_u8(eq, weights);
        uint8x16_t p0 = vpaddq_u8(masked, masked);
        uint8x16_t p1 = vpaddq_u8(p0, p0);
        uint8x16_t p2 = vpaddq_u8(p1, p1);
        uint16_t mask16 = vgetq_lane_u16(vreinterpretq_u16_u8(p2), 0);
        while (mask16 != 0) {
            unsigned tz = (unsigned)__builtin_ctz((unsigned)mask16);
            if (count < out_cap) {
                out_offsets[count] = (uint64_t)(offset + tz);
            }
            ++count;
            mask16 &= (uint16_t)(mask16 - 1U);
        }
        offset += 16;
    }

    while (offset < len) {
        if (data[offset] == delim) {
            if (count < out_cap) {
                out_offsets[count] = (uint64_t)offset;
            }
            ++count;
        }
        ++offset;
    }
    return count;
#else
    return logforge_c_scalar_scan_delimiters(data, len, delim, out_offsets, out_cap);
#endif
}

size_t logforge_c_neon_count_delimiters(
    const uint8_t *data,
    size_t len,
    uint8_t delim
) {
    return logforge_c_neon_scan_delimiters(data, len, delim, NULL, 0);
}

#ifdef LOGFORGE_PROBE_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern size_t logforge_asm_scan_delimiters(
    const uint8_t *data,
    size_t len,
    uint8_t delim,
    uint64_t *out_offsets,
    size_t out_cap
);

static double elapsed_us(struct timespec a, struct timespec b) {
    return ((double)(b.tv_sec - a.tv_sec) * 1e6) + ((double)(b.tv_nsec - a.tv_nsec) * 1e-3);
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void fill_synthetic(uint8_t *buf, size_t n, uint64_t seed) {
    static const char *tpls[4] = {
        "{\"timestamp\":\"2026-11-21T18:26:00.123456+07:00\",\"level\":\"info\",\"message\":\"gateway request accepted\",\"latency_us\":42}",
        "2026-11-21 18:26:01.005Z WARN stream chunk alignment verified||ok",
        "ts=1795266362.500 level=error msg=\"retry backoff\" host=node-01",
        "{\"ts\":1795266363123456,\"severity\":\"debug\",\"event\":\"heartbeat\",\"ok\":true}"
    };
    uint64_t state = seed ? seed : 0x9E3779B97F4A7C15ULL;
    size_t pos = 0;
    while (pos < n) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const char *line = tpls[state & 3U];
        size_t llen = strlen(line);
        size_t rem = n - pos;
        if (rem > llen) {
            memcpy(buf + pos, line, llen);
            buf[pos + llen] = '\n';
            pos += llen + 1;
        } else {
            memcpy(buf + pos, line, rem);
            pos += rem;
        }
    }
}

typedef size_t (*scan_fn_t)(const uint8_t *, size_t, uint8_t, uint64_t *, size_t);

static void run_bench(
    scan_fn_t fn,
    const uint8_t *buf,
    size_t len,
    uint64_t *out,
    size_t cap,
    int warmup,
    int iters,
    size_t *out_count,
    double *out_median,
    double *out_p95,
    double *out_min
) {
    double *samples = (double *)malloc((size_t)iters * sizeof(double));
    size_t count = 0;
    for (int i = 0; i < warmup; ++i) {
        count = fn(buf, len, '\n', out, cap);
    }
    for (int i = 0; i < iters; ++i) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        count = fn(buf, len, '\n', out, cap);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        samples[i] = elapsed_us(t0, t1);
    }
    qsort(samples, (size_t)iters, sizeof(double), cmp_double);
    *out_count = count;
    *out_min = samples[0];
    *out_median = (iters % 2) ? samples[iters / 2] : 0.5 * (samples[iters / 2 - 1] + samples[iters / 2]);
    int p95_idx = (int)((double)iters * 0.95 + 0.999999) - 1;
    if (p95_idx < 0) p95_idx = 0;
    if (p95_idx >= iters) p95_idx = iters - 1;
    *out_p95 = samples[p95_idx];
    free(samples);
}

int main(int argc, char **argv) {
    size_t len = (argc > 1) ? (size_t)strtoull(argv[1], NULL, 10) : 1048576ULL;
    int warmup = (argc > 2) ? atoi(argv[2]) : 10;
    int iters = (argc > 3) ? atoi(argv[3]) : 50;
    uint64_t seed = (argc > 4) ? (uint64_t)strtoull(argv[4], NULL, 10) : 20261121ULL;

    uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
    uint64_t *out_sc = (uint64_t *)malloc((len + 1) * sizeof(uint64_t));
    uint64_t *out_c = (uint64_t *)malloc((len + 1) * sizeof(uint64_t));
    uint64_t *out_asm = (uint64_t *)malloc((len + 1) * sizeof(uint64_t));
    fill_synthetic(buf, len, seed);

    size_t c_sc = 0, c_neon = 0, c_asm = 0;
    double med_sc = 0, p95_sc = 0, min_sc = 0;
    double med_neon = 0, p95_neon = 0, min_neon = 0;
    double med_asm = 0, p95_asm = 0, min_asm = 0;

    run_bench(logforge_c_scalar_scan_delimiters, buf, len, out_sc, len + 1, warmup, iters, &c_sc, &med_sc, &p95_sc, &min_sc);
    run_bench(logforge_c_neon_scan_delimiters, buf, len, out_c, len + 1, warmup, iters, &c_neon, &med_neon, &p95_neon, &min_neon);
    run_bench(logforge_asm_scan_delimiters, buf, len, out_asm, len + 1, warmup, iters, &c_asm, &med_asm, &p95_asm, &min_asm);

    int parity_ok = (c_sc == c_neon) && (c_sc == c_asm)
        && (memcmp(out_sc, out_c, c_sc * sizeof(uint64_t)) == 0)
        && (memcmp(out_sc, out_asm, c_sc * sizeof(uint64_t)) == 0);

    printf(
        "{\"size_bytes\":%zu,\"warmup\":%d,\"iters\":%d,\"seed\":%llu,\"parity_ok\":%s,"
        "\"c_scalar\":{\"min_us\":%.3f,\"median_us\":%.3f,\"p95_us\":%.3f,\"matches\":%zu},"
        "\"c_neon\":{\"min_us\":%.3f,\"median_us\":%.3f,\"p95_us\":%.3f,\"matches\":%zu},"
        "\"asm_aarch64_neon\":{\"min_us\":%.3f,\"median_us\":%.3f,\"p95_us\":%.3f,\"matches\":%zu}}\n",
        len, warmup, iters, (unsigned long long)seed, parity_ok ? "true" : "false",
        min_sc, med_sc, p95_sc, c_sc,
        min_neon, med_neon, p95_neon, c_neon,
        min_asm, med_asm, p95_asm, c_asm
    );

    free(buf);
    free(out_sc);
    free(out_c);
    free(out_asm);
    return parity_ok ? 0 : 1;
}
#endif
