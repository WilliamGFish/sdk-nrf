/* drivers/net/dect_nrplus.h */
#ifndef ZEPHYR_DRIVERS_NET_DECT_NRPLUS_H_
#define ZEPHYR_DRIVERS_NET_DECT_NRPLUS_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>

struct dect_nrplus_dev_ctx {
	struct net_if *iface;
	cvg_service_type_t cvg_service_type;	
	k_tid_t rx_thread_id;
	K_THREAD_STACK_MEMBER(rx_stack, CONFIG_DECT_NRPLUS_RX_STACK_SIZE);
};

#endif /* ZEPHYR_DRIVERS_NET_DECT_NRPLUS_H_ */