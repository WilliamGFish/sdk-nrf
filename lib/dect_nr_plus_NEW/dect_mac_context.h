/* dect_mac/dect_mac_context.h */
#ifndef DECT_MAC_CONTEXT_H__
#define DECT_MAC_CONTEXT_H__

#include <zephyr/kernel.h>
#include <stdint.h>
#include <stdbool.h>
#include "dect_mac_sm.h"        // For dect_mac_state_t, dect_mac_role_t, pending_op_type_t
// Note: dect_mac_api.h includes this for mac_sdu_t, creating a potential circular dependency
// if mac_sdu_t definition is *only* in dect_mac_api.h and dect_harq_tx_process_t needs it.
// To resolve, mac_sdu_t could be in a more basic types file, or use forward declaration if only pointers needed.
// For now, assuming dect_mac_api.h might have been included before by a top-level include,
// or we ensure mac_sdu_t is defined before dect_harq_tx_process_t.
// Let's move mac_sdu_t to a types file or ensure it's defined before its use in HARQ struct.
// For this output, I'll assume mac_sdu_t from "dect_mac_api.h" is somehow visible or we define it here.

// Forward declaration for mac_sdu_t if defined elsewhere and only pointer is needed
struct mac_sdu;


// --- Constants for array sizes and configurations ---
#ifndef MAX_HARQ_PROCESSES // Already in dect_mac_sm.h, ensure consistency
#define MAX_HARQ_PROCESSES 8
#endif
#define MAX_PEERS_PER_FT 8
#define MAX_MOBILITY_CANDIDATES 5
#define MAX_SUBSLOTS_IN_FRAME_NOMINAL 48 // For 10ms frame, 5 symbols/subslot, symbol dur ~41.67us => subslot ~208.3us
#define FRAME_DURATION_MS_NOMINAL 10
#define NOMINAL_SLOT_DURATION_MS 10 // Assuming 1 slot = 1 frame for some calculations
                                    // ETSI: 1 slot is 24 subslots = 120 symbols.
                                    // Duration = 120 * 41.66us = 5000us = 5ms if symbol duration is ~41.66us.
                                    // If frame is 10ms and has 2 slots, then this is consistent.
                                    // If NRF_MODEM_DECT_SYMBOL_DURATION = 2880 ticks,
                                    // 1 symbol = 2880 / 69120 kHz = 41.666... us
                                    // 1 subslot = 5 symbols = 208.333... us
                                    // 1 slot = 24 subslots = 5000 us = 5 ms.
                                    // 1 frame = 2 slots = 48 subslots = 10 ms.
#define SUB нашем_SLOTS_PER_ETSI_SLOT 24


#define SCAN_MEAS_DURATION_SLOTS_CONFIG 2 // e.g. 2 ETSI slots = 48 subslots = 10ms for background scan measurement
#define MAX_RACH_ATTEMPTS_CONFIG 5

#ifndef DEFAULT_DECT_CARRIER
#define DEFAULT_DECT_CARRIER 1924992 // kHz (Example: ETSI DECT EU Band: 1880-1900 MHz. This is outside.)
                                     // Let's use an ETSI example: GFSK carrier F_c = 1881.792 + k * 1.728 MHz
                                     // For k=0: 1881792 kHz. For k=1: 1883520 kHz
                                     // For US DECT 6.0: 1921.536 + k * 1.728 MHz. k=0..4
                                     // k=1 => 1923.264 MHz. k=2 => 1924.992 MHz (used as example)
#endif

#ifndef RSSI_HYSTERESIS_DB
#define RSSI_HYSTERESIS_DB 3
#endif

#ifndef DEFAULT_TX_POWER_CODE
#define DEFAULT_TX_POWER_CODE 0b0111 // Example: 0 dBm (ETSI Table 6.2.1-3a/3b code 0111 is 0dBm)
#endif

#ifndef MAX_MAC_PDU_SIZE_FOR_PCC_CALC // Should match CONFIG_DECT_MAC_PDU_MAX_SIZE - 1 (MAC Hdr Type octet)
#define MAX_MAC_PDU_SIZE_FOR_PCC_CALC 1637 // If CONFIG_DECT_MAC_PDU_MAX_SIZE is 1638 (true ETSI MAC PDU max)
#endif

#ifndef HARQ_ACK_TIMEOUT_MS
#define HARQ_ACK_TIMEOUT_MS 50
#endif

#ifndef MAX_HARQ_RETRIES
#define MAX_HARQ_RETRIES 3
#endif

// --- Context-related Type Definitions ---

// Re-define mac_sdu_t here if not visible from dect_mac_api.h to break circular dependency for HARQ struct
// This definition must exactly match the one in dect_mac_api.h
#ifndef MAC_SDU_T_DEFINED_FOR_CONTEXT
#define MAC_SDU_T_DEFINED_FOR_CONTEXT
#ifndef CONFIG_DECT_MAC_SDU_MAX_SIZE
#define CONFIG_DECT_MAC_SDU_MAX_SIZE 1636
#endif
typedef struct mac_sdu {
    void *fifo_reserved;
    uint8_t data[CONFIG_DECT_MAC_SDU_MAX_SIZE];
    uint16_t len;
    uint16_t target_peer_short_rd_id;
    // --- Fields for DLC ARQ Status Reporting ---
    bool dlc_status_report_required;
    uint16_t dlc_sn_for_status;    
} mac_sdu_t;
#endif


#ifndef HPC_RX_WINDOW_SIZE
#define HPC_RX_WINDOW_SIZE 64 // Example: Allow receiving HPCs up to 63 behind the newest known
#endif
#ifndef HPC_RX_FORWARD_WINDOW_MAX_ADVANCE
#define HPC_RX_FORWARD_WINDOW_MAX_ADVANCE 1024 // Max jump ahead for HPC to prevent huge skips
#endif
#ifndef MAX_MIC_FAILURES_BEFORE_HPC_RESYNC
#define MAX_MIC_FAILURES_BEFORE_HPC_RESYNC 3 // Example: after 3 MIC fails, request HPC resync
#endif


/** @brief Information about a peer device. */
typedef struct {
    bool is_valid;
    bool is_secure;
    bool is_fully_identified;
    uint32_t long_rd_id;
    uint16_t short_rd_id;
    int16_t rssi_2; // Q7.1 format
    uint16_t operating_carrier;

    // Security related per peer
    uint32_t hpc; // Peer's last known TX HPC (tracked by us for IV construction on RX)
    uint32_t highest_rx_peer_hpc; // Highest validated HPC received from this peer in a MAC Sec Info IE
                                  // Used for window-based validation. Initialized to 0 or first valid HPC.
    bool peer_requested_hpc_resync; // True if this peer sent us a Resync Request for our TX HPC
    uint8_t consecutive_mic_failures; // Count of MIC failures for PDUs from this peer

    // ... (pending_feedback_to_send and num_pending_feedback_items as before) ...
    struct {
        bool valid;
        bool is_ack;
        uint8_t harq_process_num_for_peer;
    } pending_feedback_to_send[2];
    uint8_t num_pending_feedback_items;

} dect_mac_peer_info_t;


// ETSI TS 103 636-4, Table 6.4.3.3-1 Resource Allocation Bitmap related enums
typedef enum {
    RES_ALLOC_TYPE_RELEASE_ALL = 0b00,
    RES_ALLOC_TYPE_DOWNLINK    = 0b01,
    RES_ALLOC_TYPE_UPLINK      = 0b10,
    RES_ALLOC_TYPE_BIDIR       = 0b11,
} dect_alloc_type_t;

typedef enum {
    RES_ALLOC_REPEAT_SINGLE         = 0b000,
    RES_ALLOC_REPEAT_FRAMES         = 0b001,
    RES_ALLOC_REPEAT_SUBSLOTS       = 0b010,
    RES_ALLOC_REPEAT_FRAMES_GROUP   = 0b011,
    RES_ALLOC_REPEAT_SUBSLOTS_GROUP = 0b100,
} dect_repeat_type_t;

// ETSI TS 103 636-4, Table 6.4.2.3-1 (Cluster Beacon IE Fields)
typedef struct {
    uint8_t sfn;
    bool tx_power_present;
    bool power_constraints_active;
    bool frame_offset_present;
    bool next_channel_present;
    bool time_to_next_present;
    uint8_t network_beacon_period_code;
    uint8_t cluster_beacon_period_code;
    uint8_t count_to_trigger_code;
    uint8_t rel_quality_code;
    uint8_t min_quality_code;
    uint8_t clusters_max_tx_power_code; // Valid if tx_power_present
    bool    frame_offset_is_16bit;      // Helper: True if mu implies 16-bit FO field
    uint16_t frame_offset_value;        // Valid if frame_offset_present
    uint16_t next_cluster_channel_val;  // Valid if next_channel_present (as "Next Cluster Channel")
    uint32_t time_to_next_us;           // Valid if time_to_next_present
} dect_mac_cluster_beacon_ie_fields_t;

// ETSI TS 103 636-4, Table 6.4.3.4-1 (RACH Info IE Fields)
// This structure holds fields that are actually part of the beacon IE when serialized
typedef struct {
    bool repeat_type_is_subslots;
    bool sfn_validity_present;
    bool channel_field_present;
    bool channel2_field_present;
    bool max_len_type_is_slots;
    bool dect_delay_for_response;
    uint16_t start_subslot_index;    // 8 or 9 bits, based on mu
    bool length_type_is_slots;       // For the "Length" field that follows start_subslot
    uint8_t num_subslots_or_slots;   // 7 bits, actual count
    uint8_t max_rach_pdu_len_units;  // 7 bits, actual count
    uint8_t cwmin_sig_code;          // 3 bits
    uint8_t cwmax_sig_code;          // 3 bits
    uint8_t repetition_code;         // 2 bits (ETSI: 00=1, 01=2, 10=4, 11=8 repetitions)
    uint8_t response_window_subslots_val_minus_1; // Value for 8-bit field (actual value+1)
    uint8_t sfn_value;               // If sfn_validity_present
    uint8_t validity_frames;         // If sfn_validity_present
    uint16_t channel_abs_freq_num;   // If channel_field_present
    uint16_t channel2_abs_freq_num;  // If channel2_field_present
} dect_mac_rach_info_ie_fields_t;


/** @brief Information about a peer device. */
typedef struct {
    bool is_valid;
    bool is_secure;
    bool is_fully_identified;
    uint32_t long_rd_id;
    uint16_t short_rd_id;
    int16_t rssi_2; // Q7.1 format
    uint16_t operating_carrier;
    uint32_t hpc; // Peer's last known TX HPC (tracked by us)

    struct { // Pending HARQ feedback TO SEND to this peer
        bool valid;
        bool is_ack;
        uint8_t harq_process_num_for_peer; // Peer's HARQ proc num we are ACK/NACKing
    } pending_feedback_to_send[2]; // Max 2 feedback items per nRF Feedback Format 3
    uint8_t num_pending_feedback_items;

    // Other peer-specific state (timers, QoS, schedules) can be added here
    // e.g. struct k_timer link_supervision_timer;
} dect_mac_peer_info_t;

/** @brief Stores a parsed resource allocation schedule for a link. */
typedef struct {
    bool is_active;
    dect_alloc_type_t alloc_type; // For this entry (UL, DL, or if BIDIR, this struct might represent one direction)
    // For DL part (or if alloc_type is DL)
    uint16_t dl_start_subslot;
    uint8_t dl_duration_subslots; // Actual number of subslots
    bool dl_length_is_slots;
    // For UL part (or if alloc_type is UL)
    uint16_t ul_start_subslot;
    uint8_t ul_duration_subslots;
    bool ul_length_is_slots;

    dect_repeat_type_t repeat_type;
    uint8_t repetition_value;       // Actual value from IE (e.g., 1 means every frame/subslot)
    uint8_t validity_value;         // Actual value from IE (0xFF for permanent)
    uint16_t channel;
    uint64_t next_occurrence_modem_time;
    uint8_t sfn_of_initial_occurrence; // SFN from ResAlloc IE or SFN when non-SFN schedule activated
    uint64_t schedule_init_modem_time; // Modem time when schedule was parsed/activated
    // Flags to know if start_subslot fields are 8 or 9 bits (based on mu of the link)
    bool res1_is_9bit_subslot; // True if dl_start_subslot implies 9 bits
    bool res2_is_9bit_subslot; // True if ul_start_subslot implies 9 bits (for BIDIR context)
} dect_mac_schedule_t;

/** @brief Tracks a potential mobility handover candidate FT for a PT. */
typedef struct {
    bool is_valid;
    uint16_t short_rd_id;
    uint32_t long_rd_id;
    uint16_t operating_carrier;
    int16_t rssi_2;
    uint8_t trigger_count_remaining;
    dect_mac_rach_info_ie_fields_t rach_params_from_beacon; // Parsed from candidate's beacon
} dect_mobility_candidate_t;

/** @brief Parameters for Random Access Channel (RACH) advertised by FT, stored by PT. */
typedef struct {
    dect_mac_rach_info_ie_fields_t advertised_beacon_ie_fields; // Parsed from FT's beacon
    // Derived/Operational values
    uint16_t rach_operating_channel; // Actual carrier to use for RACH TX
    uint16_t cw_min_val;             // Calculated 2^cwmin_sig_code
    uint16_t cw_max_val;             // Calculated 2^cwmax_sig_code
    uint32_t response_window_duration_us;
} dect_ft_rach_params_t; // Stored by PT for its target/associated FT

/** @brief Tracks the state of a single HARQ transmission process. */
typedef struct {
    bool is_active;
    bool needs_retransmission;
    uint8_t redundancy_version;
    uint8_t tx_attempts;
    mac_sdu_t *sdu; // Pointer to the MAC SDU (DLC PDU) being transmitted
    uint16_t original_psn;
    uint32_t original_hpc;
    struct k_timer retransmission_timer;
    uint16_t peer_short_id_for_ft_dl; // For FT: Target PT ShortID for this DL HARQ process
    uint16_t scheduled_carrier;       // For reTX: original carrier
    uint64_t scheduled_tx_start_time; // For reTX: original target start time
} dect_harq_tx_process_t;

/** @brief Stores PHY-specific latency values in microseconds. */
typedef struct {
    uint32_t scheduled_operation_startup_us;
    uint32_t scheduled_operation_transition_us;
    uint32_t idle_to_active_rx_us;
    uint32_t idle_to_active_tx_us;
    uint32_t active_to_idle_rx_us;
    uint32_t active_to_idle_tx_us;
    // Add other relevant latencies as needed
} dect_phy_latency_values_t;

/** @brief Stores MAC layer configuration parameters. */
typedef struct {
    int8_t rssi_threshold_min_dbm;  // RSSI-1 "free" threshold (ETSI RSSI_THRESHOLD_MIN)
    int8_t rssi_threshold_max_dbm;  // RSSI-1 "busy" threshold (ETSI RSSI_THRESHOLD_MAX)
    uint8_t rach_cw_min_idx;        // Code for Cwmin_sig (0-7) -> actual CW_MIN = 8 * 2^code
    uint8_t rach_cw_max_idx;        // Code for Cwmax_sig (0-7) -> actual CW_MAX = 8 * 2^code
    uint32_t rach_response_window_ms;
    uint32_t keep_alive_period_ms;
    uint32_t mobility_scan_interval_ms;
    uint32_t ft_cluster_beacon_period_ms;
    uint32_t ft_network_beacon_period_ms; // (Currently not sending separate Network Beacons)
    uint8_t max_assoc_retries;
    bool ft_policy_secure_on_assoc;
    uint8_t default_tx_power_code;  // For PCC transmit_power field (4 bits)
    uint8_t default_data_mcs_code;  // For PCC df_mcs field (3 or 4 bits depending on PCC type)
} dect_mac_config_params_t;

/** @brief Common timers and state for RACH procedure. */
typedef struct {
    struct k_timer rach_backoff_timer;
    struct k_timer rach_response_window_timer;
    uint8_t rach_cw_current_idx; // Current contention window code (0-7, maps to Cwmin_sig to Cwmax_sig)
} dect_mac_rach_context_t;

/** @brief Contains all state specific to the Portable Termination (PT) role. */
typedef struct {
    dect_mac_peer_info_t target_ft;
    dect_mac_peer_info_t associated_ft;
    
    dect_mobility_candidate_t mobility_candidates[MAX_MOBILITY_CANDIDATES];
    struct k_timer keep_alive_timer;
    struct k_timer mobility_scan_timer;
    dect_ft_rach_params_t current_ft_rach_params; // Parsed from associated/target FT's beacon
    uint8_t current_assoc_retries;
    dect_mac_schedule_t dl_schedule; // Schedule for downlink data from FT
    dect_mac_schedule_t ul_schedule; // Schedule for uplink data to FT
} pt_context_t;

// Forward declare k_fifo; already done if this header includes kernel.h
struct k_fifo;
typedef struct { // Helper struct for FT's per-peer TX FIFOs
    struct k_fifo high_priority_fifo;
    struct k_fifo reliable_data_fifo;
    struct k_fifo best_effort_fifo;
} dect_mac_peer_tx_fifo_set_t;

/** @brief Contains all state specific to the Fixed Termination (FT) role. */
typedef struct {
    dect_mac_peer_info_t connected_pts[MAX_PEERS_PER_FT];
    dect_mac_schedule_t peer_schedules[MAX_PEERS_PER_FT]; // Uplink/Downlink schedules for each PT
    dect_mac_peer_tx_fifo_set_t peer_tx_data_fifos[MAX_PEERS_PER_FT]; // Per-PT TX data queues for DL

    uint8_t sfn;
    uint8_t sfn_for_last_beacon_tx; // SFN value used in the most recently sent/scheduled beacon
    uint16_t operating_carrier;
    struct k_timer beacon_timer;
    dect_ft_rach_params_t advertised_rach_params; // RACH params FT puts in its beacon
    uint16_t last_rach_pt_short_id;
    int16_t last_rach_rssi2;
    uint16_t last_assoc_resp_pt_short_id;

    bool keys_provisioned_for_peer[MAX_PEERS_PER_FT];
    uint8_t peer_integrity_keys[MAX_PEERS_PER_FT][16];
    uint8_t peer_cipher_keys[MAX_PEERS_PER_FT][16];
} ft_context_t;

/** @brief The single, global context structure for the entire MAC layer. */
typedef struct dect_mac_context {
    dect_mac_state_t state;
    dect_mac_role_t role;
    dect_mac_config_params_t config;

    uint32_t own_long_rd_id;
    uint16_t own_short_rd_id;
    uint32_t network_id_32bit; // Full 32-bit Network ID

    uint32_t pending_op_handle;
    pending_op_type_t pending_op_type;

    dect_mac_rach_context_t rach_context;

    dect_harq_tx_process_t harq_tx_processes[MAX_HARQ_PROCESSES];
    uint16_t psn; // Own Packet Sequence Number for outgoing MAC PDUs (12-bit)
    uint32_t hpc; // Own Hyper Packet Counter for security TX (32-bit)

    dect_phy_latency_values_t phy_latency;

    // Global Master Pre-Shared Key (PSK) - Provisioned or hardcoded
    uint8_t master_psk[16];
    bool master_psk_provisioned;

    // Session keys derived from PSK (used by PT for its FT link)
    // For FT, per-peer keys are in ft_context_t. These might be unused or template for FT.
    uint8_t integrity_key[16];
    uint8_t cipher_key[16];
    bool keys_provisioned; // For PT: Are session keys derived? For FT: Are *its own global/template* keys set (if any)?
    uint8_t current_key_index; // Currently active key index (0-7) for MAC Security Info IE
    bool send_mac_sec_info_ie_on_next_tx;

    uint64_t last_known_modem_time;
    uint64_t ft_sfn_zero_modem_time_anchor; // For FT: Modem time of its SFN 0. For PT: Estimated from FT beacon.
    uint8_t  current_sfn_at_anchor_update;  // SFN value when anchor was last updated (PT uses FT's beacon SFN)

    union {
        pt_context_t pt;
        ft_context_t ft;
    } role_ctx;

} dect_mac_context_t;

#endif /* DECT_MAC_CONTEXT_H__ */