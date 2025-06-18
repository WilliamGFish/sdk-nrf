
#ifndef DECT_MAC_PHY_TBS_TABLES_H__
#define DECT_MAC_PHY_TBS_TABLES_H__

#include <stdint.h>

// Constants for table dimensions (can be shared with dect_mac_phy_ctrl.c if needed there too)
#define TBS_MAX_MCS_INDEX 11   // MCS0 to MCS11
#define TBS_MAX_SUB_SLOTS_J 16 // Corresponds to j=1 to 16 subslots (PCC packet_length field 0-15)

// ETSI TS 103 636-3 V2.1.1 (2024-10), Table C.2-1:
// PDSCH Transport block size Tb(j) (in bits) for single slot transmission,
// single spatial stream, with maximum turbo code block size of 2048 bits.
// This table is for: mu=1, beta=1
// Indexed as: tbs_single_slot_mu1_beta1[MCS_INDEX][j-1_SUBOTS]
static const uint16_t tbs_single_slot_mu1_beta1[TBS_MAX_MCS_INDEX + 1][TBS_MAX_SUB_SLOTS_J] = {
    // j=     1,     2,     3,     4,     5,     6,     7,     8,      9,     10,     11,     12,     13,     14,     15,     16
    /*MCS0*/{  136,   344,   520,   760,   936,  1128,  1320,  1576,   1768,   1992,   2168,   2424,   2616,   2808,   3000,   3192},
    /*MCS1*/{  296,   712,  1064,  1448,  1800,  2104,  2424,  2872,   3128,   3576,   3832,   4320,   4576,   4832,   5408,   5736},
    /*MCS2*/{  456,  1064,  1576,  2104,  2616,  3064,  3576,  4224,   4576,   5216,   5536,   6208,   6592,   6984,   7752,   8144},
    /*MCS3*/{  616,  1448,  2104,  2808,  3512,  4096,  4768,  5600,   6048,   6816,   7240,   8144,   8648,   9152,  10000,  10456},
    /*MCS4*/{  936,  2168,  3192,  4256,  5344,  6208,  7240,  8480,   9152,  10328,  10960,  12280,  13032,  13784,  15040,  15760},
    /*MCS5*/{ 1128,  2616,  3832,  5080,  6368,  7456,  8648, 10000,  10960,  12280,  13032,  14560,  15520,  16480,  18000,  18928},
    /*MCS6*/{ 1320,  3064,  4512,  6048,  7560,  8832, 10328, 11904,  13032,  14560,  15520,  17376,  18496,  19608,  21408,  22528},
    /*MCS7*/{ 1576,  3576,  5216,  6984,  8648, 10000, 11904, 13784,  15040,  16736,  17920,  20032,  21408,  22528,  24704,  26016},
    /*MCS8*/{ 1768,  4224,  6208,  8144, 10000, 11904, 13784, 15760,  17376,  19256,  20736,  23104,  24704,  26016,  28416,  30000},
    /*MCS9*/{ 2104,  4768,  6984,  9152, 11280, 13032, 15040, 17376,  18928,  21088,  22528,  25312,  26880,  28416,  31040,  32800},
    /*MCS10*/{2424,  5536,  8144, 10456, 13032, 15040, 17376, 20032,  21920,  24704,  26016,  29120,  31040,  32800,  35776,  37760},
    /*MCS11*/{2872,  6208,  9152, 11904, 14560, 16736, 19256, 22528,  24704,  27424,  29120,  32800,  34816,  36736,  40000,  42112}
};

// TODO: Add other TBS tables as needed, e.g., for different mu, beta, or multi-slot transmissions
// Example:
// static const uint16_t tbs_single_slot_mu2_beta1[TBS_MAX_MCS_INDEX + 1][TBS_MAX_SUB_SLOTS_J] = { ... };
// static const uint16_t tbs_dual_slot_mu1_beta1[TBS_MAX_MCS_INDEX + 1][TBS_MAX_SUB_SLOTS_J * 2] = { ... }; // Note j would be different for multi-slot

#endif /* DECT_MAC_PHY_TBS_TABLES_H__ */