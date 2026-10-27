/* Fixed artifacts-only v1 wire. All integers are unsigned, big endian.
 * Canonical scope digest binds evaluation/Run/generation/policy/Gate/profile,
 * repository/head/tree, target and source ownership. Manifest is correlation,
 * NOT a helper content proof; Supervisor independently verifies full content.
 * No struct is serialized (no native padding/endian dependence).
 */
#ifndef UAS_ARTIFACT_PROTOCOL_H
#define UAS_ARTIFACT_PROTOCOL_H
#if !defined(__x86_64__) || defined(__ILP32__)
#error "artifacts v1 requires the qualified Linux x86-64 ABI"
#endif
#include <stddef.h>
#include <stdint.h>
#define AG_CHANNEL_FD 3
#define AG_TARGET_FD 4
#define AG_UID 65530
#define AG_SUPERVISOR_UID 65533
#define AG_ENDPOINT "/uas/gate/gate.sock"
#define AG_TARGETS "uas/gate-targets"
#ifndef AG_EVALUATOR
#ifdef UAS_ARTIFACT_PROBE
/* Explicit disposable-VM test binary only, never selected by GateHelperLaunch. */
#define AG_EVALUATOR "/opt/uas/bin/artifact-confinement-probe"
#else
#define AG_EVALUATOR "/opt/uas/bin/artifact-evaluator"
#endif
#endif
#ifndef AG_NPROC
#define AG_NPROC 1U
#endif
#ifndef AG_FSIZE
#define AG_FSIZE 0U
#endif
#define AG_HEADER_BYTES 104U
#define AG_ITEM_BYTES 60U
#define AG_MAX_ITEMS 128U
#define AG_MAX_PATH_BYTES 4095U
#define AG_MAX_PATH_SCALARS 1024U
#define AG_MAX_COMPONENT_BYTES 255U
#define AG_MAX_DEPTH 32U
#define AG_MAX_ENTRIES 512U
#define AG_MAX_BLOB_BYTES (4U * 1024U * 1024U)
#define AG_MAX_TARGET_BYTES (8U * 1024U * 1024U)
#define AG_MAX_REQUEST_BYTES (1024U * 1024U)
#define AG_MAX_OUTPUT_BYTES (128U * 1024U)
#define AG_MAX_RECORD_BYTES 16384U
#define AG_WALL_SECONDS 15U
#define AG_CPU_SECONDS 5U
#define AG_MEMORY_BYTES (128U * 1024U * 1024U)
#define AG_MAX_FDS 64U
#define AG_TYPE_MISSING 3U
#define AG_TYPE_FILE 1U
#define AG_TYPE_DIRECTORY 2U
#define AG_TYPE_ERROR 4U
static inline uint32_t ag_u32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static inline uint64_t ag_u64(const unsigned char *p) {
    return ((uint64_t)ag_u32(p)<<32)|ag_u32(p+4);
}
static inline void ag_put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);
    p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;
}
static inline void ag_put64(unsigned char *p, uint64_t v) {
    ag_put32(p,(uint32_t)(v>>32));ag_put32(p+4,(uint32_t)v);
}
#endif
