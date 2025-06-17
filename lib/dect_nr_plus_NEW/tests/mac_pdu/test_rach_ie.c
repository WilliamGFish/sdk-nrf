/* tests/mac_pdu/test_rach_ie.c */
// Brief Overview: Test program for serializing and deserializing the RACH Info IE.
// It sets up various field configurations, serializes, then parses back and compares.

/*
To integrate and run this conceptual test:
Populate dect_mac_rach_info_ie_fields_t: The callers in dect_mac_sm_ft.c (when building a beacon) and dect_mac_sm_pt.c (when parsing a beacon) need to correctly set/get the mu_value_for_ft_beacon field.
FT side (Serializer): When ft_send_beacon_action calls serialize_rach_info_ie_payload, the rach_fields->mu_value_for_ft_beacon should be set to the FT's own mu value (from ctx->phy_link_params.mu or a similar field representing its operating numerology for the link on which it's beaconing).
PT side (Parser): When pt_handle_phy_pdc_internal calls parse_rach_info_ie_payload after receiving a beacon's PDC, it needs to pass the mu value of the transmitting FT. This mu would typically be learned by the PT from the FT's RD Capability IE. If RD Capabilities are not yet fully exchanged/parsed, the PT might have to assume a default mu (e.g., 1) for parsing the RACH Info IE from an unknown FT. This is a bootstrapping challenge.
Run the Test Program:
Compile and run the test program.
Carefully examine the "Original" vs. "Parsed" printouts.
Check the hex dump of the serialized IE against your manual bit-by-bit construction based on the ETSI spec and the input fields to verify the serializer.
Ensure the parser correctly reconstructs all fields, especially start_subslot_index for both 8-bit and 9-bit cases.
*/


#include <zephyr/kernel.h>
#include <zephyr/ztest.h> // If using Ztest, otherwise use printk for results
#include <string.h>
#include <stdio.h> // For snprintf
#include <zephyr/sys/util.h> // For ARRAY_SIZE

// Include the headers for the functions and structs we are testing
#include "dect_mac_pdu.h"     // For (de)serialization functions and IE_TYPE_RACH_INFO
#include "dect_mac_context.h" // For dect_mac_rach_info_ie_fields_t

// Helper to print dect_mac_rach_info_ie_fields_t for comparison
static void print_rach_fields(const char *label, const dect_mac_rach_info_ie_fields_t *fields)
{
    printk("%s RACH Fields (mu_val_for_ft_beacon: %u):\n", label, fields->mu_value_for_ft_beacon);
    printk("  Flags: RepeatSubslots:%d SFNVal:%d ChanPres:%d Chan2Pres:%d MaxLenSlots:%d DECTDelay:%d\n",
           fields->repeat_type_is_subslots, fields->sfn_validity_present,
           fields->channel_field_present, fields->channel2_field_present,
           fields->max_len_type_is_slots, fields->dect_delay_for_response);
    printk("  StartSS: %u, LenTypeSlots: %d, NumUnits: %u, MaxRACHLenUnits: %u\n",
           fields->start_subslot_index, fields->length_type_is_slots,
           fields->num_subslots_or_slots, fields->max_rach_pdu_len_units);
    printk("  CWminCode: %u, CWmaxCode: %u, RepCode: %u, RespWinVal-1: %u\n",
           fields->cwmin_sig_code, fields->cwmax_sig_code,
           fields->repetition_code, fields->response_window_subslots_val_minus_1);
    if (fields->sfn_validity_present) {
        printk("  SFNVal: %u, ValidityFrames: %u\n", fields->sfn_value, fields->validity_frames);
    }
    if (fields->channel_field_present) {
        printk("  Channel1: %u (0x%X)\n", fields->channel_abs_freq_num, fields->channel_abs_freq_num);
    }
    if (fields->channel2_field_present) {
        printk("  Channel2: %u (0x%X)\n", fields->channel2_abs_freq_num, fields->channel2_abs_freq_num);
    }
    printk("-----\n");
}

// Test case function
// Returns true on success, false on failure
static bool run_single_rach_ie_test(const char* test_name, const dect_mac_rach_info_ie_fields_t *original_fields)
{
    uint8_t serialized_buf[64]; // Generous buffer for RACH IE
    memset(serialized_buf, 0xAA, sizeof(serialized_buf)); // Fill with known pattern
    dect_mac_rach_info_ie_fields_t parsed_fields;
    int serialized_len;
    int parse_ret;
    bool pass = true;

    printk("\n--- Test Case: %s ---\n", test_name);
    print_rach_fields("Original", original_fields);

    // Serialize
    serialized_len = serialize_rach_info_ie_payload(serialized_buf, sizeof(serialized_buf), original_fields);
    if (serialized_len < 0) {
        printk("TEST FAIL: Serialization failed with error %d\n", serialized_len);
        return false;
    }
    printk("Serialized IE (len %d bytes):\n", serialized_len);
    for(int i=0; i<serialized_len; i++) { printk("%02X ", serialized_buf[i]); }
    printk("\n");

    // Parse
    // Pass the mu value that was used for serialization to the parser
    parse_ret = parse_rach_info_ie_payload(serialized_buf, (uint16_t)serialized_len,
                                           original_fields->mu_value_for_ft_beacon, &parsed_fields);
    if (parse_ret < 0) {
        printk("TEST FAIL: Parsing failed with error %d\n", parse_ret);
        return false;
    }
    print_rach_fields("Parsed  ", &parsed_fields);

    // Compare - This needs to be field by field. Using memcmp is too strict due to potential padding/uninit in struct.
    if (original_fields->repeat_type_is_subslots != parsed_fields.repeat_type_is_subslots) { printk("MISMATCH: repeat_type_is_subslots\n"); pass = false; }
    if (original_fields->sfn_validity_present != parsed_fields.sfn_validity_present) { printk("MISMATCH: sfn_validity_present\n"); pass = false; }
    if (original_fields->channel_field_present != parsed_fields.channel_field_present) { printk("MISMATCH: channel_field_present\n"); pass = false; }
    if (original_fields->channel2_field_present != parsed_fields.channel2_field_present) { printk("MISMATCH: channel2_field_present\n"); pass = false; }
    if (original_fields->max_len_type_is_slots != parsed_fields.max_len_type_is_slots) { printk("MISMATCH: max_len_type_is_slots\n"); pass = false; }
    if (original_fields->dect_delay_for_response != parsed_fields.dect_delay_for_response) { printk("MISMATCH: dect_delay_for_response\n"); pass = false; }

    if (original_fields->start_subslot_index != parsed_fields.start_subslot_index) { printk("MISMATCH: start_subslot_index\n"); pass = false; }
    if (original_fields->length_type_is_slots != parsed_fields.length_type_is_slots) { printk("MISMATCH: length_type_is_slots\n"); pass = false; }
    if (original_fields->num_subslots_or_slots != parsed_fields.num_subslots_or_slots) { printk("MISMATCH: num_subslots_or_slots\n"); pass = false; }
    if (original_fields->max_rach_pdu_len_units != parsed_fields.max_rach_pdu_len_units) { printk("MISMATCH: max_rach_pdu_len_units\n"); pass = false; }

    if (original_fields->cwmin_sig_code != parsed_fields.cwmin_sig_code) { printk("MISMATCH: cwmin_sig_code\n"); pass = false; }
    if (original_fields->cwmax_sig_code != parsed_fields.cwmax_sig_code) { printk("MISMATCH: cwmax_sig_code\n"); pass = false; }
    if (original_fields->repetition_code != parsed_fields.repetition_code) { printk("MISMATCH: repetition_code\n"); pass = false; }
    if (original_fields->response_window_subslots_val_minus_1 != parsed_fields.response_window_subslots_val_minus_1) { printk("MISMATCH: response_window_subslots_val_minus_1\n"); pass = false; }

    if (original_fields->sfn_validity_present) {
        if (original_fields->sfn_value != parsed_fields.sfn_value) { printk("MISMATCH: sfn_value\n"); pass = false; }
        if (original_fields->validity_frames != parsed_fields.validity_frames) { printk("MISMATCH: validity_frames\n"); pass = false; }
    }
    if (original_fields->channel_field_present) {
        if (original_fields->channel_abs_freq_num != parsed_fields.channel_abs_freq_num) { printk("MISMATCH: channel_abs_freq_num\n"); pass = false; }
    }
    if (original_fields->channel2_field_present) {
        if (original_fields->channel2_abs_freq_num != parsed_fields.channel2_abs_freq_num) { printk("MISMATCH: channel2_abs_freq_num\n"); pass = false; }
    }
    // mu_value_for_ft_beacon should be copied correctly by parser if it's part of the struct being compared
    if (original_fields->mu_value_for_ft_beacon != parsed_fields.mu_value_for_ft_beacon) { printk("MISMATCH: mu_value_for_ft_beacon\n"); pass = false; }


    if (pass) {
        printk("TEST PASS: %s\n", test_name);
    } else {
        printk("TEST FAIL: %s - Mismatched fields found.\n", test_name);
    }
    return pass;
}

// Main test function (if not using Ztest)
void main_test_rach_ie(void) // Rename main if this is a standalone test app
{
    printk("Starting RACH Info IE (De)Serialization Tests...\n");
    int pass_count = 0;
    int fail_count = 0;

    // Test Case 1: Basic, mu=1 (8-bit StartSS), no optional fields
    dect_mac_rach_info_ie_fields_t tc1_orig = {
        .mu_value_for_ft_beacon = 1, // <= 4 implies 8-bit StartSS
        .repeat_type_is_subslots = false, .sfn_validity_present = false,
        .channel_field_present = false, .channel2_field_present = false,
        .max_len_type_is_slots = false, .dect_delay_for_response = false,
        .start_subslot_index = 10, .length_type_is_slots = false, .num_subslots_or_slots = 4, // 4 subslots long
        .max_rach_pdu_len_units = 20, // Max PDU is 20 units (subslots/slots)
        .cwmin_sig_code = 2, .cwmax_sig_code = 5, .repetition_code = 0, // Repeat every frame
        .response_window_subslots_val_minus_1 = 47, // 48 subslots
    };
    if (run_single_rach_ie_test("Basic mu=1 (8-bit SS), no optionals", &tc1_orig)) pass_count++; else fail_count++;

    // Test Case 2: mu=5 (9-bit StartSS), all optional fields present
    dect_mac_rach_info_ie_fields_t tc2_orig = {
        .mu_value_for_ft_beacon = 5, // > 4 implies 9-bit StartSS
        .repeat_type_is_subslots = true, .sfn_validity_present = true,
        .channel_field_present = true, .channel2_field_present = true,
        .max_len_type_is_slots = true, .dect_delay_for_response = true,
        .start_subslot_index = 300, // Needs 9 bits
        .length_type_is_slots = true, .num_subslots_or_slots = 2, // 2 slots long
        .max_rach_pdu_len_units = 10, // Max PDU is 10 slots
        .cwmin_sig_code = 1, .cwmax_sig_code = 4, .repetition_code = 1, // Repeat every 2 subslots
        .response_window_subslots_val_minus_1 = 23, // 24 subslots
        .sfn_value = 100, .validity_frames = 200,
        .channel_abs_freq_num = 1234, .channel2_abs_freq_num = 1235,
    };
    if (run_single_rach_ie_test("Advanced mu=5 (9-bit SS), all optionals", &tc2_orig)) pass_count++; else fail_count++;

    // Test Case 3: Edge StartSS for 8-bit (max value 255)
    dect_mac_rach_info_ie_fields_t tc3_orig = tc1_orig; // Copy tc1
    tc3_orig.mu_value_for_ft_beacon = 1;
    tc3_orig.start_subslot_index = 255;
    if (run_single_rach_ie_test("Edge StartSS=255 (8-bit)", &tc3_orig)) pass_count++; else fail_count++;

    // Test Case 4: Edge StartSS for 9-bit (max value 511)
    dect_mac_rach_info_ie_fields_t tc4_orig = tc2_orig; // Copy tc2
    tc4_orig.mu_value_for_ft_beacon = 5;
    tc4_orig.start_subslot_index = 511;
    if (run_single_rach_ie_test("Edge StartSS=511 (9-bit)", &tc4_orig)) pass_count++; else fail_count++;

    // Test Case 5: Only SFN optional present
    dect_mac_rach_info_ie_fields_t tc5_orig = tc1_orig;
    tc5_orig.mu_value_for_ft_beacon = 1;
    tc5_orig.sfn_validity_present = true;
    tc5_orig.sfn_value = 50; tc5_orig.validity_frames = 10;
    if (run_single_rach_ie_test("Only SFN optional (mu=1)", &tc5_orig)) pass_count++; else fail_count++;

    // Test Case 6: Only Channel1 optional present
    dect_mac_rach_info_ie_fields_t tc6_orig = tc1_orig;
    tc6_orig.mu_value_for_ft_beacon = 1;
    tc6_orig.channel_field_present = true;
    tc6_orig.channel_abs_freq_num = 2000;
    if (run_single_rach_ie_test("Only Channel1 optional (mu=1)", &tc6_orig)) pass_count++; else fail_count++;


    printk("\nRACH IE Test Summary: %d Passed, %d Failed\n", pass_count, fail_count);
}

// If using Ztest, you'd use ztest_unit_test and assertions.
// For a standalone test, you'd call main_test_rach_ie() from your main().
// Example for Ztest:
#ifdef CONFIG_ZTEST
ZTEST_SUITE(rach_ie_tests, NULL, NULL, NULL, NULL, NULL);
ZTEST(rach_ie_tests, test_rach_ie_basic_mu1) {
    dect_mac_rach_info_ie_fields_t tc = { /* ... fill tc1_orig ... */ };
    tc.mu_value_for_ft_beacon = 1;
    // ... set other fields ...
    zassert_true(run_single_rach_ie_test("Basic mu=1", &tc), "Basic mu=1 test failed");
}
ZTEST(rach_ie_tests, test_rach_ie_adv_mu5) {
    dect_mac_rach_info_ie_fields_t tc = { /* ... fill tc2_orig ... */ };
    tc.mu_value_for_ft_beacon = 5;
    // ... set other fields ...
    zassert_true(run_single_rach_ie_test("Advanced mu=5", &tc), "Advanced mu=5 test failed");
}
// Add more ZTEST cases...
#endif // CONFIG_ZTEST

/*
To run this (if not using Ztest):
1. Save as `test_rach_ie.c` in a suitable location (e.g., `src/tests/`).
2. Add it to your `CMakeLists.txt`.
3. In your application's `main()` (e.g., in `dect_mac_main.c` temporarily, or a dedicated test main),
   call `main_test_rach_ie();`.
4. Build and run. Observe printk output.
*/