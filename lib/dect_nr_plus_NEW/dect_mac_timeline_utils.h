

#ifndef DECT_MAC_TIME_UTILS_H__
#define DECT_MAC_TIME_UTILS_H__

/**
 * @brief Calculates the target modem time for an event based on SFN and subslot.
 *
 * @param ctx Pointer to the global MAC context.
 * @param sfn_zero_anchor_time The modem time corresponding to SFN 0 of the relevant entity.
 * @param sfn_of_anchor_relevance The SFN value at which sfn_zero_anchor_time was valid/established.
 * @param target_sfn_val The target SFN for the event.
 * @param target_subslot_idx The target subslot index within the target SFN.
 * @param link_mu_code The mu_code (0-7) of the link/entity whose timeline is being used.
 * @param link_beta_code The beta_code (0-15) of the link/entity. (Currently unused by subslot duration, but good for completeness)
 * @return The calculated target modem time, or UINT64_MAX on error.
 */
uint64_t calculate_target_modem_time(dect_mac_context_t *ctx, uint64_t sfn_zero_anchor_time,
                                     uint8_t sfn_of_anchor_relevance, uint8_t target_sfn_val,
                                     uint16_t target_subslot_idx,
                                     uint8_t link_mu_code, uint8_t link_beta_code);




#endif /* DECT_MAC_TIME_UTILS_H__ */