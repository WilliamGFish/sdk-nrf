/* drivers/net/dect_nrplus.c */

#define LOG_LEVEL CONFIG_DECT_NRPLUS_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(dect_nrplus_l2, LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_core.h>

#include "dect_nrplus.h"
#include "dect_cvg.h" // Our custom CVG API

static void dect_nrplus_rx_thread(void *p1, void *p2, void *p3)
{
	struct dect_nrplus_dev_ctx *ctx = p1;
	struct net_if *iface = ctx->iface;
	struct net_pkt *pkt = NULL;
	int ret;

	LOG_INF("DECT NR+ RX thread started for iface %p.", iface);

	while (1) {
		// Allocate a new network packet buffer for the incoming data.
		// It's better to allocate before blocking on receive to be ready.
		// The timeout specifies how long to wait for a free buffer.
		pkt = net_pkt_rx_alloc_with_buffer(iface,
						   CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE,
						   AF_UNSPEC, 0, K_MSEC(500));
		if (!pkt) {
			LOG_WRN("Failed to allocate net_pkt for RX. Retrying allocation.");
			// If we fail to get a buffer, retry after a short sleep to avoid
			// busy-looping if the system is out of buffers.
			k_sleep(K_MSEC(100));
			continue;
		}

		// Block and wait for a complete SDU from our CVG layer.
		// net_buf_tailroom(pkt->buffer) gives the size of our allocated buffer.
		size_t received_len = net_buf_tailroom(pkt->buffer);
		ret = dect_cvg_receive(pkt->buffer->data, &received_len, K_FOREVER);
		if (ret < 0) {
			if (ret == -EMSGSIZE) {
				LOG_ERR("CVG receive error: buffer too small. This shouldn't happen with our allocation size.");
			} else {
				LOG_WRN("dect_cvg_receive returned error %d. Retrying.", ret);
			}

			// Free the unused packet and loop to try again.
			net_pkt_unref(pkt);
			continue;
		}

		if (received_len == 0) {
			LOG_WRN("Received empty payload from CVG. Discarding.");
			net_pkt_unref(pkt);
			continue;
		}

		// Finalize the packet by setting its actual length.
		net_buf_add(pkt->buffer, received_len);

		LOG_DBG("RX: Received %zu bytes from CVG, passing to net_recv_data()", received_len);

		// Inject the packet into the network stack.
		// The stack will take ownership of the pkt.
		ret = net_recv_data(iface, pkt);
		if (ret < 0) {
			LOG_ERR("Failed to inject packet into network stack: %d", ret);
			// If injection fails, we must free the packet ourselves.
			net_pkt_unref(pkt);
		}

		// The packet is now owned by the network stack, so we don't unref it on success.
		// Loop to allocate a new one for the next receive operation.
	}
}

static void dect_nrplus_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct dect_nrplus_dev_ctx *ctx = dev->data;

	LOG_INF("Initializing DECT NR+ L2 network interface %p", iface);
	ctx->iface = iface;

	// The RX thread will be started when the interface is enabled.
}

static int dect_nrplus_iface_send(struct net_if *iface, struct net_pkt *pkt)
{
	const struct device *dev = net_if_get_device(iface);
	struct dect_nrplus_dev_ctx *ctx = dev->data;
	int ret;
	size_t ip_packet_len = net_pkt_get_len(pkt);

	LOG_DBG("SEND: pkt %p, len %zu, service type %d", pkt, ip_packet_len, ctx->cvg_service_type);

	if (ip_packet_len == 0) {
		LOG_WRN("Dropping empty packet.");
		return 0;
	}

	// The net_pkt might be fragmented. We need to copy it into a single,
	// contiguous buffer before passing it to the CVG layer.
	// We can use a stack buffer for reasonably sized packets to avoid heap allocation.
	if (ip_packet_len > CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE) {
		LOG_ERR("IP packet too large (%zu > %d). Dropping.",
			ip_packet_len, CONFIG_DECT_DLC_MAX_SDU_PAYLOAD_SIZE);
		return -EMSGSIZE;
	}
	uint8_t tx_buf[ip_packet_len];

	ret = net_pkt_read(pkt, tx_buf, ip_packet_len);
	if (ret < 0) {
		LOG_ERR("Failed to read net_pkt into buffer: %d", ret);
		return ret;
	}

	// Now send the contiguous IP packet to our CVG layer.
	// The CVG layer will handle wrapping this in CVG/DLC headers.
	ret = dect_cvg_send(ctx->cvg_service_type, tx_buf, ip_packet_len);
	if (ret < 0) {
		LOG_ERR("dect_cvg_send failed: %d", ret);
		// The return code from our CVG layer might be -ENOMEM or -EMSGSIZE.
		// The net stack doesn't have a great way to handle backpressure,
		// so we just return the error code.
		return ret;
	}

	return 0;
}

// Define the L2 API structure required by the network interface
static enum net_l2_flags dect_nrplus_l2_flags(struct net_if *iface)
{
	// Declare that this L2 does not handle its own IP address management
	// and is suitable for 6LoWPAN.
	return NET_L2_POINTOPOINT | NET_L2_NO_ARP;
}

// Populate the L2 API structure with our functions
NET_L2_INIT(DECT_NRPLUS_L2, dect_nrplus_l2_flags);

// Populate the main interface API structure
static struct net_if_api dect_nrplus_if_api = {
	.iface_api.init = dect_nrplus_iface_init,
	.iface_api.send = dect_nrplus_iface_send,
	.iface_api.enable = dect_nrplus_iface_enable,
	// No need for get_ptp_clock, can be added later if needed.
};

static int dect_nrplus_driver_init(const struct device *dev)
{
	struct dect_nrplus_dev_ctx *ctx = dev->data;

	ctx->cvg_service_type = DT_PROP(dev->of_node, cvg_service_type);

	LOG_INF("DECT NR+ L2 driver initialized, device: %s, CVG Service: %d",
		dev->name, ctx->cvg_service_type);
	return 0;
}


// Instantiate the driver using DT_DRV_COMPAT
// This creates a device instance for each `nordic,dect-nrplus` node in devicetree.
#define DECT_NRPLUS_INIT(inst)							\
	static struct dect_nrplus_dev_ctx dect_nrplus_ctx_##inst;		\
										\
	NET_DEVICE_DT_INST_DEFINE(inst,						\
				  dect_nrplus_driver_init,			\
				  NULL,						\
				  &dect_nrplus_ctx_##inst,			\
				  NULL,						\
				  CONFIG_DECT_NRPLUS_INIT_PRIORITY,		\
				  &dect_nrplus_if_api,				\
				  &DECT_NRPLUS_L2,				\
				  1500); /* MTU */				\

DT_INST_FOREACH_STATUS_OKAY(DECT_NRPLUS_INIT)