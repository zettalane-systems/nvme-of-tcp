/*
 * NVMe over TCP host code. Based on NVMe over Fabrics RDMA host code.
 * Copyright (c) 2015-2016 HGST, a Western Digital Company.
 * Copyright (c) 2016-2017 Rip Sohan <rip.sohan@verrko.com>
 * Copyright (c) 2016-2017 Bert Kenward <bert.kenward@solarflare.com>
 * Copyright (c) 2016-2017 Lucian Carata <lucian.carata@cl.cam.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/blk-mq.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <linux/rwlock.h>
#include <linux/scatterlist.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/nvme.h>
#include <linux/scatterlist.h>
#include <asm/unaligned.h>

#include <linux/nvme-rdma.h>
#include <uapi/linux/tcp.h>

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
#include "rhel-release-7.4/nvme.h"
#include "rhel-release-7.4/fabrics.h"
#define	NVME_AQ_DEPTH	NVMF_AQ_DEPTH
#else
#include "rhel-release-7.5/nvme.h"
#include "rhel-release-7.5/fabrics.h"
#endif

static inline int blk_rq_is_passthrough(struct request *rq)
{
	return (rq->cmd_type == REQ_TYPE_DRV_PRIV);
}
#define blk_rq_nr_phys_segments(rq)	 rq->nr_phys_segments

#define NVME_TCP_IP_PORT 11345

#define NVME_TCP_MAX_HW_SECTORS  256

/*
 * We handle AEN commands ourselves and don't even let the
 * block layer know about them.
 */
#define NVME_TCP_NR_AEN_COMMANDS      1
#define NVME_TCP_AQ_BLKMQ_DEPTH       \
	(NVME_AQ_DEPTH - NVME_TCP_NR_AEN_COMMANDS)

struct nvme_tcp_queue;

struct nvme_tcp_request {
	struct nvme_request	req;
	void			*sqe;
	u32			num_sge;
	int			nents;
	bool			inline_data;
	struct nvme_tcp_queue  *queue;
	struct list_head        list;
	struct sg_table		sg_table;
	struct scatterlist     *current_sg;
	struct scatterlist	first_sgl[];
};

enum nvme_tcp_queue_flags {
	NVME_TCP_Q_CONNECTED = (1 << 0),
	NVME_TCP_Q_DELETING = (1 << 1),
	NVME_TCP_Q_LIVE = (1 << 2),
};

struct nvme_tcp_data_state {
	enum {
		NVME_TCP_IN_HEADER,
		NVME_TCP_IN_PAYLOAD,
	} state;
	unsigned int       offset;
	struct request    *rq;
};

struct nvme_tcp_queue {
	int			queue_size;
	struct socket           *socket;
	struct kref             socket_ref;
	struct workqueue_struct *workqueue;
	struct work_struct      swork;
	struct work_struct      rwork;
	struct nvme_tcp_ctrl	*ctrl;
	unsigned long		flags;
	spinlock_t              recv_lock;
	spinlock_t              request_lock;
	struct list_head        request_list;
	struct nvme_tcp_data_state rx_state;
	struct nvme_tcp_data_state tx_state;
	struct nvme_completion  cqe;
};

struct nvme_tcp_ctrl {
	/* read and written in the hot path */
	spinlock_t		lock;

	/* read only in the hot path */
	struct nvme_tcp_queue	*queues;
	u32			queue_count;

	/* other member variables */
	struct blk_mq_tag_set	tag_set;
	u16			wq_index;
	u16			queue_wq_index;
	struct workqueue_struct *workqueue;
	struct work_struct	delete_work;
	struct work_struct	reset_work;
	struct work_struct	err_work;

	struct nvme_tcp_request async_event_req;

	int			reconnect_delay;
	struct delayed_work	reconnect_work;

	struct list_head	list;

	struct blk_mq_tag_set	admin_tag_set;

	u64			cap;

	union {
		struct sockaddr addr;
		struct sockaddr_in addr_in;
	};

	struct nvme_ctrl	ctrl;
};

static void nvme_tcp_queue_socket_release(struct kref *kref);
static int nvme_tcp_recv_one(struct nvme_tcp_queue *queue, int tag);

static inline struct nvme_tcp_ctrl *to_tcp_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_tcp_ctrl, ctrl);
}

static LIST_HEAD(nvme_tcp_ctrl_list);
static DEFINE_MUTEX(nvme_tcp_ctrl_mutex);

/* XXX: really should move to a generic header sooner or later.. */
static inline void put_unaligned_le24(u32 val, u8 *p)
{
	*p++ = val;
	*p++ = val >> 8;
	*p++ = val >> 16;
}

static inline int nvme_tcp_queue_idx(struct nvme_tcp_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static void nvme_tcp_free_qe(struct nvme_tcp_request *req)
{
	kfree(req->sqe);
}

static int nvme_tcp_alloc_qe(struct nvme_tcp_request *req, size_t capsule_size)
{
	req->sqe = kzalloc(capsule_size, GFP_KERNEL);
	if (!req->sqe)
		return -ENOMEM;

	return 0;
}

static int nvme_tcp_reinit_request(void *data, struct request *rq)
{
	return 0;
}

static void __nvme_tcp_exit_request(struct nvme_tcp_ctrl *ctrl,
		struct request *rq, unsigned int queue_idx)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	nvme_tcp_free_qe(req);
}

static void nvme_tcp_exit_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx)
{
	return __nvme_tcp_exit_request(data, rq, hctx_idx + 1);
}

static void nvme_tcp_exit_admin_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx)
{
	return __nvme_tcp_exit_request(data, rq, 0);
}

static int __nvme_tcp_init_request(struct nvme_tcp_ctrl *ctrl,
		struct request *rq, unsigned int queue_idx)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_queue *queue = &ctrl->queues[queue_idx];
	int ret;

	if (queue_idx >= ctrl->queue_count)
		return -EINVAL;

	ret = nvme_tcp_alloc_qe(req, sizeof(struct nvme_command));
	if (ret)
		return ret;

	req->queue = queue;
	INIT_LIST_HEAD(&req->list);
	return 0;
}

static int nvme_tcp_init_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return __nvme_tcp_init_request(data, rq, hctx_idx + 1);
}

static int nvme_tcp_init_admin_request(void *data, struct request *rq,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return __nvme_tcp_init_request(data, rq, 0);
}

static int nvme_tcp_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = data;
	struct nvme_tcp_queue *queue = &ctrl->queues[hctx_idx + 1];

	if (hctx_idx >= ctrl->queue_count)
		return -EINVAL;

	hctx->driver_data = queue;
	return 0;
}

static int nvme_tcp_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_tcp_ctrl *ctrl = data;
	struct nvme_tcp_queue *queue = &ctrl->queues[0];

	if (hctx_idx != 0)
		return -EINVAL;

	hctx->driver_data = queue;
	return 0;
}

static void nvme_tcp_destroy_queue(struct nvme_tcp_queue *queue)
{
	kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
}

static void nvme_tcp_sock_write_space(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	kref_get(&queue->socket_ref);
	if (!queue_work(queue->workqueue, &queue->swork))
		kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvme_tcp_sock_data_ready(struct sock *sk)
{
	struct nvme_tcp_queue *queue;

	read_lock_bh(&sk->sk_callback_lock);
	queue = sk->sk_user_data;
	kref_get(&queue->socket_ref);
	if (!queue_work(queue->workqueue, &queue->rwork))
		kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void nvme_tcp_sock_register_callback(struct socket *sock,
					    struct nvme_tcp_queue *queue)
{
	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready = nvme_tcp_sock_data_ready;
	sock->sk->sk_write_space = nvme_tcp_sock_write_space;
	sock->sk->sk_user_data = queue;
	write_unlock_bh(&sock->sk->sk_callback_lock);
}

static struct socket *nvme_tcp_connect_to_target(struct sockaddr_in *addr_in)
{
	struct socket *sock = NULL;
	int optval;
	int rc;

	rc = sock_create_kern(/* current->nsproxy->net_ns,*/
			      AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (rc < 0)
		return ERR_PTR(rc);

	rc = kernel_connect(sock, (struct sockaddr *)addr_in,
			    sizeof(*addr_in), 0);
	if (rc < 0)
		goto err;

	sock->sk->sk_rcvtimeo = usecs_to_jiffies(100);
	optval = 1;
	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			(char*)&optval, sizeof(optval));

	return sock;

err:
	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	return ERR_PTR(rc);
}

static void nvme_tcp_conn_rwork(struct work_struct *work)
{
	struct nvme_tcp_queue *queue;
	int count = 0;
	int ret;

	queue = container_of(work, struct nvme_tcp_queue, rwork);

	while (test_bit(NVME_TCP_Q_CONNECTED, &queue->flags)) {
		ret = nvme_tcp_recv_one(queue, -1);
		if (ret < 0)
			goto out;

		if (count++ == 10) {
			cond_resched();
			count = 0;
		}
	}

out:
	kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
}

static int nvme_tcp_send(struct socket *socket, void *buf, size_t buf_len,
			 int flags)
{
	struct msghdr msg = { };
	struct kvec iov;

	msg.msg_flags = flags | MSG_DONTWAIT | MSG_NOSIGNAL;

	iov.iov_base = buf;
	iov.iov_len = buf_len;

	return kernel_sendmsg(socket, &msg, &iov, 1, iov.iov_len);
}

static int nvme_tcp_recv(struct socket *socket, void *buf, size_t buf_len)
{
	struct msghdr msg = { };
	struct kvec iov;
	int rc;

	iov.iov_base = buf;
	iov.iov_len = buf_len;

	rc = kernel_recvmsg(socket, &msg, &iov, 1, iov.iov_len, MSG_DONTWAIT);
	if (rc == 0)
		rc = -ENOTCONN;

	return rc;
}

static void nvme_tcp_conn_swork(struct work_struct *work)
{
	struct nvme_tcp_queue *queue;
	int count = 0;
	bool has_payload;
	int rc;

	queue = container_of(work, struct nvme_tcp_queue, swork);

//printk("nvme_tcp_conn_swork: q %p state %x flags %x rq %p\n", queue, queue->tx_state.state, queue->flags, queue->tx_state.rq);

	while (test_bit(NVME_TCP_Q_CONNECTED, &queue->flags)) {
		struct nvme_tcp_request *req;
		struct request *rq;
		int tx_size;
		u8 *tx_buf;

		if (queue->tx_state.rq) {
			rq = queue->tx_state.rq;
			req = blk_mq_rq_to_pdu(rq);
		} else {
			spin_lock(&queue->request_lock);
			if (!list_empty(&queue->request_list)) {
				req = list_first_entry(&queue->request_list,
						struct nvme_tcp_request, list);
				list_del_init(&req->list);
			} else {
				req = NULL;
			}
			spin_unlock(&queue->request_lock);
			if (req) {
				rq = blk_mq_rq_from_pdu(req);
				queue->tx_state.rq = rq;
				queue->tx_state.state = NVME_TCP_IN_HEADER;
				queue->tx_state.offset = 0;
			} else {
				break;
			}
		}

		switch (queue->tx_state.state) {
		case NVME_TCP_IN_HEADER:
			has_payload = (rq_data_dir(rq) == WRITE) &&
					blk_rq_bytes(rq);

			tx_size = sizeof(struct nvme_command) -
					queue->tx_state.offset;
			tx_buf = (u8 *)req->sqe + queue->tx_state.offset;

			rc = nvme_tcp_send(queue->socket, tx_buf, tx_size,
					has_payload ? MSG_MORE : 0);

			if (rc == -EAGAIN)
				goto out_done;
			if (rc <= 0)
				goto out_err;
			if (rc < tx_size) {
				queue->tx_state.offset += rc;
				goto out_done;
			}

			/* We've sent the entire SQE. */
			queue->tx_state.offset = 0;

			/* AEN commands have no block-layer representation */
			if (unlikely(nvme_tcp_queue_idx(queue) == 0 &&
				     req == &queue->ctrl->async_event_req)) {
				queue->tx_state.rq = NULL;
				break;
			}

			if (!has_payload) {
				queue->tx_state.rq = NULL;
				break;
			}

			req->current_sg = req->first_sgl;
			queue->tx_state.state = NVME_TCP_IN_PAYLOAD;
			/* Fall through. */
		case NVME_TCP_IN_PAYLOAD:
			/* Iterate over all SG entries until EAGAIN or done. */
			while (req->current_sg) {
				int offset;

				tx_size = req->current_sg->length -
						queue->tx_state.offset;
				offset = req->current_sg->offset +
						queue->tx_state.offset;

				rc = kernel_sendpage(queue->socket,
						sg_page(req->current_sg),
						offset, tx_size, MSG_DONTWAIT | MSG_NOSIGNAL);

				if (rc == -EAGAIN)
					goto out_done;
				if (rc <= 0)
					goto out_err;
				if (rc < tx_size) {
					queue->tx_state.offset += rc;
					goto out_done;
				}

				/* Sent all of current_sg */
				queue->tx_state.offset = 0;
				req->current_sg = sg_next(req->current_sg);
			}

			/* All data sent. */
			queue->tx_state.rq = NULL;

			break;
		}

		if (count++ > 10) {
			cond_resched();
			count = 0;
		}
	}

out_done:
//printk("nvme_tcp_conn_swork: leave rc = %d rq = %p\n", rc, queue->tx_state.rq);

	kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
	return;

out_err:
	kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
	dev_err(queue->ctrl->ctrl.device,
		"%s: send returned error [err = %d]\n", __func__, rc);
}

static int nvme_tcp_init_queue(struct nvme_tcp_ctrl *ctrl,
		int idx, size_t queue_size)
{
	struct nvme_tcp_queue *queue;
	u16 wq_index;

	queue = &ctrl->queues[idx];
	queue->ctrl = ctrl;
	queue->queue_size = queue_size;

	queue->socket = nvme_tcp_connect_to_target(&ctrl->addr_in);
	if (IS_ERR(queue->socket))
		return PTR_ERR(queue->socket);

	kref_init(&queue->socket_ref);

	spin_lock_init(&queue->recv_lock);

	spin_lock_init(&queue->request_lock);
	INIT_LIST_HEAD(&queue->request_list);

	wq_index = ctrl->queue_wq_index++;
	queue->workqueue = alloc_ordered_workqueue("nvme-tcp-ctrl%04x-q%04x", 0,
			ctrl->wq_index, wq_index);
	if (!queue->workqueue)
		return -ENOMEM;
	INIT_WORK(&queue->rwork, nvme_tcp_conn_rwork);
	INIT_WORK(&queue->swork, nvme_tcp_conn_swork);
	nvme_tcp_sock_register_callback(queue->socket, queue);

	clear_bit(NVME_TCP_Q_DELETING, &queue->flags);
	set_bit(NVME_TCP_Q_CONNECTED, &queue->flags);

	return 0;
}

static void nvme_tcp_queue_socket_release(struct kref *kref)
{
	struct nvme_tcp_queue *queue;

	queue = container_of(kref, struct nvme_tcp_queue, socket_ref);
	spin_lock(&queue->recv_lock);
	if (queue->socket)
		sock_release(queue->socket);
	queue->socket = NULL;
	destroy_workqueue(queue->workqueue);
	queue->ctrl->queue_wq_index--;
	spin_unlock(&queue->recv_lock);
}

static void nvme_tcp_stop_queue(struct nvme_tcp_queue *queue)
{
	if (test_and_clear_bit(NVME_TCP_Q_CONNECTED, &queue->flags) &&
	    queue->socket)
		kernel_sock_shutdown(queue->socket, SHUT_RDWR);
}

static void nvme_tcp_free_queue(struct nvme_tcp_queue *queue)
{
	nvme_tcp_destroy_queue(queue);
}

static void nvme_tcp_stop_and_free_queue(struct nvme_tcp_queue *queue)
{
	if (test_and_set_bit(NVME_TCP_Q_DELETING, &queue->flags))
		return;
	nvme_tcp_stop_queue(queue);
	nvme_tcp_free_queue(queue);
}

static void nvme_tcp_free_io_queues(struct nvme_tcp_ctrl *ctrl)
{
	int i;

	for (i = 1; i < ctrl->queue_count; i++)
		nvme_tcp_stop_and_free_queue(&ctrl->queues[i]);
}

static int nvme_tcp_connect_io_queues(struct nvme_tcp_ctrl *ctrl)
{
	int i, ret = 0;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvmf_connect_io_queue(&ctrl->ctrl, i);
		if (ret) {
			dev_info(ctrl->ctrl.device,
				"failed to connect i/o queue: %d\n", ret);
			goto out_free_queues;
		}
		set_bit(NVME_TCP_Q_LIVE, &ctrl->queues[i].flags);
	}

	return 0;

out_free_queues:
	nvme_tcp_free_io_queues(ctrl);
	return ret;
}

static int nvme_tcp_init_io_queues(struct nvme_tcp_ctrl *ctrl)
{
	int i, ret;

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_tcp_init_queue(ctrl, i,
				ctrl->ctrl.opts->queue_size);
		if (ret) {
			dev_info(ctrl->ctrl.device,
				"failed to initialize i/o queue: %d\n", ret);
			goto out_free_queues;
		}
	}

	return 0;

out_free_queues:
	for (i--; i >= 1; i--)
		nvme_tcp_stop_and_free_queue(&ctrl->queues[i]);

	return ret;
}

static void nvme_tcp_destroy_admin_queue(struct nvme_tcp_ctrl *ctrl)
{
	nvme_tcp_free_qe(&ctrl->async_event_req);
	nvme_tcp_stop_and_free_queue(&ctrl->queues[0]);
	blk_cleanup_queue(ctrl->ctrl.admin_q);
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
}

static void nvme_tcp_free_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);

	if (list_empty(&ctrl->list))
		goto free_ctrl;

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_del(&ctrl->list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	kfree(ctrl->queues);
	nvmf_free_options(nctrl->opts);
	destroy_workqueue(ctrl->workqueue);
free_ctrl:
	kfree(ctrl);
}

static void nvme_tcp_reconnect_ctrl_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *ctrl = container_of(to_delayed_work(work),
			struct nvme_tcp_ctrl, reconnect_work);
	bool changed;
	int ret;

	if (ctrl->queue_count > 1) {
		nvme_tcp_free_io_queues(ctrl);

		ret = blk_mq_reinit_tagset(&ctrl->tag_set);
		if (ret)
			goto requeue;
	}

	nvme_tcp_stop_and_free_queue(&ctrl->queues[0]);

	ret = blk_mq_reinit_tagset(&ctrl->admin_tag_set);
	if (ret)
		goto requeue;

	ret = nvme_tcp_init_queue(ctrl, 0, NVME_AQ_DEPTH);
	if (ret)
		goto requeue;

	blk_mq_start_stopped_hw_queues(ctrl->ctrl.admin_q, true);

	ret = nvmf_connect_admin_queue(&ctrl->ctrl);
	if (ret)
		goto stop_admin_q;

	set_bit(NVME_TCP_Q_LIVE, &ctrl->queues[0].flags);

	ret = nvme_enable_ctrl(&ctrl->ctrl, ctrl->cap);
	if (ret)
		goto stop_admin_q;

	nvme_start_keep_alive(&ctrl->ctrl);

	if (ctrl->queue_count > 1) {
		ret = nvme_tcp_init_io_queues(ctrl);
		if (ret)
			goto stop_admin_q;

		ret = nvme_tcp_connect_io_queues(ctrl);
		if (ret)
			goto stop_admin_q;
	}

	changed = nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_LIVE);
	WARN_ON_ONCE(!changed);

	if (ctrl->queue_count > 1) {
		nvme_start_queues(&ctrl->ctrl);
		nvme_queue_scan(&ctrl->ctrl);
		nvme_queue_async_events(&ctrl->ctrl);
	}

	dev_info(ctrl->ctrl.device, "Successfully reconnected\n");

	return;

stop_admin_q:
	blk_mq_stop_hw_queues(ctrl->ctrl.admin_q);
requeue:
	/* Make sure we are not resetting/deleting */
	if (ctrl->ctrl.state == NVME_CTRL_RECONNECTING) {
		dev_info(ctrl->ctrl.device,
			"Failed reconnect attempt, requeueing...\n");
		queue_delayed_work(ctrl->workqueue, &ctrl->reconnect_work,
					ctrl->reconnect_delay * HZ);
	}
}

static void nvme_tcp_error_recovery_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *ctrl = container_of(work,
			struct nvme_tcp_ctrl, err_work);
	int i;

	nvme_stop_keep_alive(&ctrl->ctrl);

	for (i = 0; i < ctrl->queue_count; i++) {
		clear_bit(NVME_TCP_Q_CONNECTED, &ctrl->queues[i].flags);
		clear_bit(NVME_TCP_Q_LIVE, &ctrl->queues[i].flags);
	}

	if (ctrl->queue_count > 1)
		nvme_stop_queues(&ctrl->ctrl);
	blk_mq_stop_hw_queues(ctrl->ctrl.admin_q);

	/* We must take care of fastfail/requeue all our inflight requests */
	if (ctrl->queue_count > 1)
		blk_mq_tagset_busy_iter(&ctrl->tag_set,
					nvme_cancel_request, &ctrl->ctrl);
	blk_mq_tagset_busy_iter(&ctrl->admin_tag_set,
				nvme_cancel_request, &ctrl->ctrl);

	dev_info(ctrl->ctrl.device, "reconnecting in %d seconds\n",
		ctrl->reconnect_delay);

	queue_delayed_work(ctrl->workqueue, &ctrl->reconnect_work,
				ctrl->reconnect_delay * HZ);
}

static void nvme_tcp_error_recovery(struct nvme_tcp_ctrl *ctrl)
{
	if (!nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_RECONNECTING))
		return;

	queue_work(ctrl->workqueue, &ctrl->err_work);
}

static void nvme_tcp_unmap_data(struct nvme_tcp_queue *queue,
		struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	if (!blk_rq_bytes(rq))
		return;

	nvme_cleanup_cmd(rq);
	sg_free_table_chained(&req->sg_table, true);
}

static int nvme_tcp_set_sg_null(struct nvme_command *c)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = 0;
	sg->length = 0;
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;

	return 0;
}

static int nvme_tcp_map_sg_inline(struct nvme_tcp_queue *queue,
		struct nvme_tcp_request *req, struct nvme_command *c,
		unsigned int len)
{
	struct nvme_sgl_desc *sg = &c->common.dptr.sgl;

	sg->addr = cpu_to_le64(queue->ctrl->ctrl.icdoff);
	sg->length = cpu_to_le32(len);
	sg->type = (NVME_SGL_FMT_DATA_DESC << 4) | NVME_SGL_FMT_OFFSET;

	req->inline_data = true;
	req->num_sge++;
	return 0;
}

static int nvme_tcp_map_data(struct nvme_tcp_queue *queue,
		struct request *rq, struct nvme_command *c)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	unsigned short phys_segments;
	unsigned int len;
	int nents;
	int ret;

	/* Check this here, rather than passing bad messages to the target. */
	if (queue->ctrl->ctrl.icdoff)
		return -EINVAL;

	req->num_sge = 1;
	req->inline_data = false;

	c->common.flags |= NVME_CMD_SGL_METABUF;
	if (req_op(rq) == REQ_OP_DISCARD)
		len = sizeof(struct nvme_dsm_range);
	else
		len = blk_rq_bytes(rq);

	if (!len)
		return nvme_tcp_set_sg_null(c);

	phys_segments = blk_rq_nr_phys_segments(rq);

	req->sg_table.sgl = req->first_sgl;
	ret = sg_alloc_table_chained(&req->sg_table, phys_segments, GFP_ATOMIC,
				req->sg_table.sgl);
	if (ret)
		return -ENOMEM;

	nents = blk_rq_map_sg(rq->q, rq, req->sg_table.sgl);
	if (nents > phys_segments) {
		sg_free_table_chained(&req->sg_table, true);
		return -EINVAL;
	}
	req->nents = nents;

	return nvme_tcp_map_sg_inline(queue, req, c, len);
}

static void nvme_tcp_post_send(struct nvme_tcp_queue *queue,
			       struct nvme_tcp_request *req)
{
	spin_lock(&queue->request_lock);
	list_add_tail(&req->list, &queue->request_list);
	spin_unlock(&queue->request_lock);

	kref_get(&queue->socket_ref);
	if (!queue_work(queue->workqueue, &queue->swork))
		kref_put(&queue->socket_ref, nvme_tcp_queue_socket_release);
}

static struct blk_mq_tags *nvme_tcp_tagset(struct nvme_tcp_queue *queue)
{
	u32 queue_idx = nvme_tcp_queue_idx(queue);

	if (queue_idx == 0)
		return queue->ctrl->admin_tag_set.tags[queue_idx];
	return queue->ctrl->tag_set.tags[queue_idx - 1];
}

static void nvme_tcp_submit_async_event(struct nvme_ctrl *arg, int aer_idx)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(arg);
	struct nvme_tcp_request *req = &ctrl->async_event_req;
	struct nvme_tcp_queue *queue = &ctrl->queues[0];
	struct nvme_command *cmd = req->sqe;

	if (WARN_ON_ONCE(aer_idx != 0))
		return;

	pr_debug("Async event submitted\n");

	memset(cmd, 0, sizeof(*cmd));
	cmd->common.opcode = nvme_admin_async_event;
	cmd->common.command_id = NVME_TCP_AQ_BLKMQ_DEPTH;
	cmd->common.flags |= NVME_CMD_SGL_METABUF;
	nvme_tcp_set_sg_null(cmd);

	nvme_tcp_post_send(queue, req);
}

/** Initial response processing.
 *
 *  Returns: -ve:  error
 *             0:  request complete
 *           +ve:  amount of data expected
 */
static int nvme_tcp_response_process(struct nvme_tcp_queue *queue, int tag)
{
	struct request *rq;
	u16 status;

	rq = blk_mq_tag_to_rq(nvme_tcp_tagset(queue), queue->cqe.command_id);
	if (!rq) {
		dev_err(queue->ctrl->ctrl.device,
			"tag 0x%x on Queue %#x not found\n",
			queue->cqe.command_id, nvme_tcp_queue_idx(queue));
		nvme_tcp_error_recovery(queue->ctrl);
		return -EINVAL;
	}

	queue->rx_state.rq = rq;
	status = le16_to_cpu(queue->cqe.status) >> 1;

	if (rq_data_dir(rq) == READ && status == 0 && blk_rq_bytes(rq)) {
		struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

		req->current_sg = req->first_sgl;
		queue->rx_state.offset = 0;
		return blk_rq_bytes(rq);
	}

	return 0;
}

/** Data reception for responses.
 *
 *  Returns: -ve:  error (including -EAGAIN if data not yet ready)
 *             0:  request completed
 */
static int nvme_tcp_response_get_data(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(queue->rx_state.rq);
	int recv_size;
	u8 *recv_buf;
	int rc;

	while (req->current_sg) {
		recv_size = req->current_sg->length - queue->rx_state.offset;
		recv_buf = sg_virt(req->current_sg);
		recv_buf += queue->rx_state.offset;

		spin_lock(&queue->recv_lock);
		rc = nvme_tcp_recv(queue->socket, recv_buf, recv_size);
		spin_unlock(&queue->recv_lock);

		if (rc < 0)
			/* Includes -EAGAIN. */
			return rc;

		if (rc < recv_size) {
			/* Still more to come. */
			queue->rx_state.offset += rc;
			return -EAGAIN;
		}

		/* Move on to the next entry. */
		queue->rx_state.offset = 0;
		req->current_sg = sg_next(req->current_sg);
	}

	return 0;
}

static int nvme_tcp_response_complete(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;
	u16 status;

	status = le16_to_cpu(queue->cqe.status) >> 1;

	req = blk_mq_rq_to_pdu(queue->rx_state.rq);
	req->req.result = queue->cqe.result;
//printk("nvme_tcp_response_complete: q %p rq %p req %p\n", queue, queue->rx_state.rq,req);
	blk_mq_complete_request(queue->rx_state.rq, status);

	queue->rx_state.state = NVME_TCP_IN_HEADER;
	queue->rx_state.rq = NULL;

	return 0;
}

static int nvme_tcp_recv_one(struct nvme_tcp_queue *queue, int tag)
{
	int recv_size;
	u8 *recv_buf;
	int rc = 0;

	switch (queue->rx_state.state) {
	case NVME_TCP_IN_HEADER:
		recv_buf = (u8 *)&queue->cqe;
		recv_buf += queue->rx_state.offset;
		recv_size = sizeof(queue->cqe) - queue->rx_state.offset;

		spin_lock(&queue->recv_lock);
		rc = nvme_tcp_recv(queue->socket, recv_buf, recv_size);
		spin_unlock(&queue->recv_lock);

		if (rc == -EAGAIN)
			return rc;

		if (rc < 0) {
			dev_err_ratelimited(queue->ctrl->ctrl.device,
					"%s: nvme_tcp_recv error [err = %d]\n",
					__func__, rc);
			return rc;
		}

		if (rc < recv_size) {
			/* Still more to come. */
			queue->rx_state.offset += rc;
			return -EAGAIN;
		}

		/*
		 * If we get here we have a complete CQE.
		 */
		queue->rx_state.offset = 0;

		/* AEN requests are special as they don't time out and can
		 * survive any kind of queue freeze and often don't respond to
		 * aborts.  We don't even bother to allocate a struct request
		 * for them but rather special case them here.
		 */
		if (nvme_tcp_queue_idx(queue) == 0 &&
		    queue->cqe.command_id >= NVME_TCP_AQ_BLKMQ_DEPTH) {
			nvme_complete_async_event(&queue->ctrl->ctrl,
					queue->cqe.status,
					&queue->cqe.result);
			return 0;
		}

		rc = nvme_tcp_response_process(queue, tag);
		if (rc < 0)
			return rc;

		if (rc == 0)
			/* No data expected. */
			return nvme_tcp_response_complete(queue);

		if (rc > 0)
			queue->rx_state.state = NVME_TCP_IN_PAYLOAD;

		/* Drop through. */

	case NVME_TCP_IN_PAYLOAD:
		rc = nvme_tcp_response_get_data(queue);
		if (rc == 0)
			return nvme_tcp_response_complete(queue);
		else
			return rc;
		break;
	}

	return rc;
}

static enum blk_eh_timer_return
nvme_tcp_timeout(struct request *rq, bool reserved)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);

	/* queue error recovery */
	nvme_tcp_error_recovery(req->queue->ctrl);

	/* fail with DNR on cmd timeout */
	rq->errors = NVME_SC_ABORT_REQ | NVME_SC_DNR;

	return BLK_EH_HANDLED;
}

static inline bool nvme_tcp_queue_is_ready(struct nvme_tcp_queue *queue,
		struct request *rq)
{
	if (unlikely(!test_bit(NVME_TCP_Q_LIVE, &queue->flags))) {
		struct nvme_command *cmd = nvme_req(rq)->cmd;

		if (!blk_rq_is_passthrough(rq) ||
		    cmd->common.opcode != nvme_fabrics_command ||
		    cmd->fabrics.fctype != nvme_fabrics_type_connect)
			return false;
	}

	return true;
}

static int nvme_tcp_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_tcp_queue *queue = hctx->driver_data;
	struct request *rq = bd->rq;
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_command *cmd = req->sqe;
	bool flush;
	int ret;

	WARN_ON_ONCE(rq->tag < 0);

	if (!nvme_tcp_queue_is_ready(queue, rq))
		return BLK_MQ_RQ_QUEUE_BUSY;

	ret = nvme_setup_cmd(ns, rq, cmd);
	if (ret != BLK_MQ_RQ_QUEUE_OK)
		return ret;

	blk_mq_start_request(rq);

	if (cmd->common.opcode == nvme_fabrics_command)
		pr_debug("Queueing fabrics command %#x\n",
				cmd->fabrics.fctype);
	else
		pr_debug("Queueing non-fabrics command %#x\n",
				cmd->common.opcode);

	ret = nvme_tcp_map_data(queue, rq, cmd);

	if (ret < 0) {
		dev_err(queue->ctrl->ctrl.device,
			     "Failed to map data (%d)\n", ret);
		nvme_cleanup_cmd(rq);
		goto err;
	}

#if 1
	if (rq->cmd_type == REQ_TYPE_FS && (rq->cmd_flags & REQ_FLUSH))
#else
	if (req_op(rq) == REQ_OP_FLUSH)
#endif
		flush = true;
	nvme_tcp_post_send(queue, req);

	return BLK_MQ_RQ_QUEUE_OK;
err:
	return (ret == -ENOMEM || ret == -EAGAIN) ?
		BLK_MQ_RQ_QUEUE_BUSY : BLK_MQ_RQ_QUEUE_ERROR;
}

static void nvme_tcp_complete_rq(struct request *rq)
{
	struct nvme_tcp_request *req = blk_mq_rq_to_pdu(rq);
	struct nvme_tcp_queue *queue = req->queue;
	int error = 0;

	nvme_tcp_unmap_data(queue, rq);

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	if (unlikely(rq->errors)) {
		if (nvme_req_needs_retry(rq, rq->errors)) {
			nvme_requeue_req(rq);
			return;
		}

		if (blk_rq_is_passthrough(rq))
			error = rq->errors;
		else
			error = nvme_error_status(rq->errors);
	}
#endif

	blk_mq_end_request(rq, error);
}
#if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,4)
static struct blk_mq_aux_ops nvme_tcp_mq_aux_ops = {
        .reinit_request = nvme_tcp_reinit_request
};
#endif

static struct blk_mq_ops nvme_tcp_mq_ops = {
#if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,4)
	.aux_ops	= &nvme_tcp_mq_aux_ops,
#endif
	.queue_rq	= nvme_tcp_queue_rq,
	.complete	= nvme_tcp_complete_rq,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	.map_queue	= blk_mq_map_queue,
	.reinit_request	= nvme_tcp_reinit_request,
#endif
	.init_request	= nvme_tcp_init_request,
	.exit_request	= nvme_tcp_exit_request,
	.init_hctx	= nvme_tcp_init_hctx,
//	.poll		= NULL,              /* TODO */
	.timeout	= nvme_tcp_timeout,
};

static struct blk_mq_ops nvme_tcp_admin_mq_ops = {
#if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,4)
	.aux_ops	= &nvme_tcp_mq_aux_ops,
#endif
	.queue_rq	= nvme_tcp_queue_rq,
	.complete	= nvme_tcp_complete_rq,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	.map_queue	= blk_mq_map_queue,
	.reinit_request	= nvme_tcp_reinit_request,
#endif
	.init_request	= nvme_tcp_init_admin_request,
	.exit_request	= nvme_tcp_exit_admin_request,
	.init_hctx	= nvme_tcp_init_admin_hctx,
	.timeout	= nvme_tcp_timeout,
};

static int nvme_tcp_configure_admin_queue(struct nvme_tcp_ctrl *ctrl)
{
	int error;

	error = nvme_tcp_init_queue(ctrl, 0, NVME_AQ_DEPTH);
	if (error)
		return error;

	memset(&ctrl->admin_tag_set, 0, sizeof(ctrl->admin_tag_set));
	ctrl->admin_tag_set.ops = &nvme_tcp_admin_mq_ops;
	ctrl->admin_tag_set.queue_depth = NVME_TCP_AQ_BLKMQ_DEPTH;
	ctrl->admin_tag_set.reserved_tags = 2; /* connect + keep-alive */
	ctrl->admin_tag_set.numa_node = NUMA_NO_NODE;
	ctrl->admin_tag_set.cmd_size = sizeof(struct nvme_tcp_request) +
		SG_CHUNK_SIZE * sizeof(struct scatterlist);
	ctrl->admin_tag_set.driver_data = ctrl;
	ctrl->admin_tag_set.nr_hw_queues = 1;
	ctrl->admin_tag_set.timeout = ADMIN_TIMEOUT;

	error = blk_mq_alloc_tag_set(&ctrl->admin_tag_set);
	if (error)
		goto out_free_queue;

	ctrl->ctrl.admin_q = blk_mq_init_queue(&ctrl->admin_tag_set);
	if (IS_ERR(ctrl->ctrl.admin_q)) {
		error = PTR_ERR(ctrl->ctrl.admin_q);
		goto out_free_tagset;
	}

	error = nvmf_connect_admin_queue(&ctrl->ctrl);
	if (error)
		goto out_cleanup_queue;

	set_bit(NVME_TCP_Q_LIVE, &ctrl->queues[0].flags);

	error = nvmf_reg_read64(&ctrl->ctrl, NVME_REG_CAP, &ctrl->cap);
	if (error) {
		dev_err(ctrl->ctrl.device,
			"prop_get NVME_REG_CAP failed\n");
		goto out_cleanup_queue;
	}

	ctrl->ctrl.sqsize =
		min_t(int, NVME_CAP_MQES(ctrl->cap) + 1, ctrl->ctrl.sqsize);
	INIT_LIST_HEAD(&ctrl->async_event_req.list);

	error = nvme_enable_ctrl(&ctrl->ctrl, ctrl->cap);
	if (error)
		goto out_cleanup_queue;

	ctrl->ctrl.max_hw_sectors = NVME_TCP_MAX_HW_SECTORS;

	error = nvme_init_identify(&ctrl->ctrl);
	if (error)
		goto out_cleanup_queue;

	error = nvme_tcp_alloc_qe(&ctrl->async_event_req,
				  sizeof(struct nvme_command));
	if (error)
		goto out_cleanup_queue;
	INIT_LIST_HEAD(&ctrl->async_event_req.list);


	nvme_start_keep_alive(&ctrl->ctrl);

	return 0;

out_cleanup_queue:
	blk_cleanup_queue(ctrl->ctrl.admin_q);
out_free_tagset:
	/* disconnect and drain the queue before freeing the tagset */
	nvme_tcp_stop_queue(&ctrl->queues[0]);
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
out_free_queue:
	nvme_tcp_free_queue(&ctrl->queues[0]);
	return error;
}

static void nvme_tcp_shutdown_ctrl(struct nvme_tcp_ctrl *ctrl)
{
	nvme_stop_keep_alive(&ctrl->ctrl);
	cancel_work_sync(&ctrl->err_work);
	cancel_delayed_work_sync(&ctrl->reconnect_work);

	if (ctrl->queue_count > 1) {
		nvme_stop_queues(&ctrl->ctrl);
		blk_mq_tagset_busy_iter(&ctrl->tag_set,
					nvme_cancel_request, &ctrl->ctrl);
		nvme_tcp_free_io_queues(ctrl);
	}

	nvme_shutdown_ctrl(&ctrl->ctrl);

	blk_mq_stop_hw_queues(ctrl->ctrl.admin_q);
	blk_mq_tagset_busy_iter(&ctrl->admin_tag_set,
				nvme_cancel_request, &ctrl->ctrl);
	nvme_tcp_destroy_admin_queue(ctrl);
}

static void __nvme_tcp_remove_ctrl(struct nvme_tcp_ctrl *ctrl, bool shutdown)
{
	nvme_uninit_ctrl(&ctrl->ctrl);
	if (shutdown)
		nvme_tcp_shutdown_ctrl(ctrl);

	if (ctrl->ctrl.tagset) {
		blk_cleanup_queue(ctrl->ctrl.connect_q);
		blk_mq_free_tag_set(&ctrl->tag_set);
	}

	nvme_put_ctrl(&ctrl->ctrl);
}

static void nvme_tcp_del_ctrl_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *ctrl = container_of(work,
				struct nvme_tcp_ctrl, delete_work);

	__nvme_tcp_remove_ctrl(ctrl, true);
}

static int __nvme_tcp_del_ctrl(struct nvme_tcp_ctrl *ctrl)
{
	if (!nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_DELETING))
		return -EBUSY;

	if (!queue_work(ctrl->workqueue, &ctrl->delete_work))
		return -EBUSY;

	return 0;
}

static int nvme_tcp_del_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
	int ret = 0;

	/*
	 * Keep a reference until all work is flushed since
	 * __nvme_tcp_del_ctrl can free the ctrl mem
	 */
	if (!kref_get_unless_zero(&ctrl->ctrl.kref))
		return -EBUSY;
	ret = __nvme_tcp_del_ctrl(ctrl);
	if (!ret)
		flush_work(&ctrl->delete_work);
	nvme_put_ctrl(&ctrl->ctrl);
	return ret;
}

static void nvme_tcp_remove_ctrl_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *ctrl = container_of(work,
				struct nvme_tcp_ctrl, delete_work);

	__nvme_tcp_remove_ctrl(ctrl, false);
}

static void nvme_tcp_reset_ctrl_work(struct work_struct *work)
{
	struct nvme_tcp_ctrl *ctrl = container_of(work,
					struct nvme_tcp_ctrl, reset_work);
	int ret;
	bool changed;

	nvme_tcp_shutdown_ctrl(ctrl);

	ret = nvme_tcp_configure_admin_queue(ctrl);
	if (ret) {
		/* ctrl is already shutdown, just remove the ctrl */
		INIT_WORK(&ctrl->delete_work, nvme_tcp_remove_ctrl_work);
		goto del_dead_ctrl;
	}

	if (ctrl->queue_count > 1) {
		ret = blk_mq_reinit_tagset(&ctrl->tag_set);
		if (ret)
			goto del_dead_ctrl;

		ret = nvme_tcp_init_io_queues(ctrl);
		if (ret)
			goto del_dead_ctrl;

		ret = nvme_tcp_connect_io_queues(ctrl);
		if (ret)
			goto del_dead_ctrl;
	}

	changed = nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_LIVE);
	WARN_ON_ONCE(!changed);

	if (ctrl->queue_count > 1) {
		nvme_start_queues(&ctrl->ctrl);
		nvme_queue_scan(&ctrl->ctrl);
		nvme_queue_async_events(&ctrl->ctrl);
	}

	return;

del_dead_ctrl:
	/* Deleting this dead controller... */
	dev_warn(ctrl->ctrl.device, "Removing after reset failure\n");
	WARN_ON(!queue_work(ctrl->workqueue, &ctrl->delete_work));
}

static int nvme_tcp_reset_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);

	if (!nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_RESETTING))
		return -EBUSY;

	if (!queue_work(ctrl->workqueue, &ctrl->reset_work))
		return -EBUSY;

	flush_work(&ctrl->reset_work);

	return 0;
}

static const struct nvme_ctrl_ops nvme_tcp_ctrl_ops = {
	.name			= "tcp",
	.module			= THIS_MODULE,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	.is_fabrics		= true,
#else
	.flags			= NVME_F_FABRICS,
#endif
	.reg_read32		= nvmf_reg_read32,
	.reg_read64		= nvmf_reg_read64,
	.reg_write32		= nvmf_reg_write32,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	.reset_ctrl		= nvme_tcp_reset_ctrl,
#endif
	.free_ctrl		= nvme_tcp_free_ctrl,
	.submit_async_event	= nvme_tcp_submit_async_event,
	.delete_ctrl		= nvme_tcp_del_ctrl,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)
	.get_subsysnqn		= nvmf_get_subsysnqn,
#endif
	.get_address		= nvmf_get_address,
};

static int nvme_tcp_create_io_queues(struct nvme_tcp_ctrl *ctrl)
{
	struct nvmf_ctrl_options *opts = ctrl->ctrl.opts;
	int ret;

	ret = nvme_set_queue_count(&ctrl->ctrl, &opts->nr_io_queues);
	if (ret)
		return ret;

	ctrl->queue_count = opts->nr_io_queues + 1;
	if (ctrl->queue_count < 2)
		return 0;

	dev_info(ctrl->ctrl.device,
		"creating %d I/O queues.\n", opts->nr_io_queues);

	ret = nvme_tcp_init_io_queues(ctrl);
	if (ret)
		return ret;

	memset(&ctrl->tag_set, 0, sizeof(ctrl->tag_set));
	ctrl->tag_set.ops = &nvme_tcp_mq_ops;
	ctrl->tag_set.queue_depth = ctrl->ctrl.opts->queue_size;
	ctrl->tag_set.reserved_tags = 1; /* fabric connect */
	ctrl->tag_set.numa_node = NUMA_NO_NODE;
	ctrl->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ctrl->tag_set.cmd_size = sizeof(struct nvme_tcp_request) +
		SG_CHUNK_SIZE * sizeof(struct scatterlist);
	ctrl->tag_set.driver_data = ctrl;
	ctrl->tag_set.nr_hw_queues = ctrl->queue_count - 1;
	ctrl->tag_set.timeout = NVME_IO_TIMEOUT;

	ret = blk_mq_alloc_tag_set(&ctrl->tag_set);
	if (ret)
		goto out_free_io_queues;
	ctrl->ctrl.tagset = &ctrl->tag_set;

	ctrl->ctrl.connect_q = blk_mq_init_queue(&ctrl->tag_set);
	if (IS_ERR(ctrl->ctrl.connect_q)) {
		ret = PTR_ERR(ctrl->ctrl.connect_q);
		goto out_free_tag_set;
	}

	ret = nvme_tcp_connect_io_queues(ctrl);
	if (ret)
		goto out_cleanup_connect_q;

	return 0;

out_cleanup_connect_q:
	blk_cleanup_queue(ctrl->ctrl.connect_q);
out_free_tag_set:
	blk_mq_free_tag_set(&ctrl->tag_set);
out_free_io_queues:
	nvme_tcp_free_io_queues(ctrl);
	return ret;
}

static int nvme_tcp_parse_ipaddr(struct sockaddr_in *in_addr, char *p)
{
	u8 *addr = (u8 *)&in_addr->sin_addr.s_addr;
	size_t buflen = strlen(p);

	/* XXX: handle IPv6 addresses */

	if (buflen > INET_ADDRSTRLEN)
		return -EINVAL;
	if (in4_pton(p, buflen, addr, '\0', NULL) == 0)
		return -EINVAL;
	in_addr->sin_family = AF_INET;
	return 0;
}

static struct nvme_ctrl *nvme_tcp_create_ctrl(struct device *dev,
		struct nvmf_ctrl_options *opts)
{
	struct nvme_tcp_ctrl *ctrl;
	int ret;
	bool changed;
	u16 port = NVME_TCP_IP_PORT;
	static u16 wq_index;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return ERR_PTR(-ENOMEM);
	ctrl->ctrl.opts = opts;
	INIT_LIST_HEAD(&ctrl->list);

	ret = nvme_tcp_parse_ipaddr(&ctrl->addr_in, opts->traddr);
	if (ret) {
		pr_err("malformed IP address passed: %s\n", opts->traddr);
		goto out_free_ctrl;
	}

	if (opts->mask & NVMF_OPT_TRSVCID) {
		ret = kstrtou16(opts->trsvcid, 0, &port);
		if (ret)
			goto out_free_ctrl;
	}
	ctrl->addr_in.sin_port = cpu_to_be16(port);

	ret = nvme_init_ctrl(&ctrl->ctrl, dev, &nvme_tcp_ctrl_ops,
				0 /* no quirks, we're perfect! */);
	if (ret)
		goto out_free_ctrl;

	ctrl->reconnect_delay = opts->reconnect_delay;
	ctrl->wq_index = wq_index++;
	ret = -ENOMEM;
	ctrl->workqueue = alloc_ordered_workqueue("nvme-tcp-ctrl%04x", 0,
			ctrl->wq_index);
	if (!ctrl->workqueue)
		goto out_free_wq;

	INIT_DELAYED_WORK(&ctrl->reconnect_work,
			nvme_tcp_reconnect_ctrl_work);

	INIT_WORK(&ctrl->err_work, nvme_tcp_error_recovery_work);
	INIT_WORK(&ctrl->delete_work, nvme_tcp_del_ctrl_work);
	INIT_WORK(&ctrl->reset_work, nvme_tcp_reset_ctrl_work);
	spin_lock_init(&ctrl->lock);

	ctrl->queue_count = opts->nr_io_queues + 1; /* +1 for admin queue */
	ctrl->ctrl.sqsize = opts->queue_size - 1;
	ctrl->ctrl.kato = opts->kato;

	ctrl->queues = kcalloc(ctrl->queue_count, sizeof(*ctrl->queues),
				GFP_KERNEL);
	if (!ctrl->queues)
		goto out_uninit_ctrl;

	ret = nvme_tcp_configure_admin_queue(ctrl);
	if (ret)
		goto out_kfree_queues;

	/* sanity check icdoff */
	if (ctrl->ctrl.icdoff) {
		dev_err(ctrl->ctrl.device, "icdoff is not supported!\n");
		goto out_remove_admin_queue;
	}

	if (opts->queue_size > ctrl->ctrl.maxcmd) {
		/* warn if maxcmd is lower than queue_size */
		dev_warn(ctrl->ctrl.device,
			"queue_size %zu > ctrl maxcmd %u, clamping down\n",
			opts->queue_size, ctrl->ctrl.maxcmd);
		opts->queue_size = ctrl->ctrl.maxcmd;
	}

	if (opts->nr_io_queues) {
		ret = nvme_tcp_create_io_queues(ctrl);
		if (ret)
			goto out_remove_admin_queue;
	}

	changed = nvme_change_ctrl_state(&ctrl->ctrl, NVME_CTRL_LIVE);
	WARN_ON_ONCE(!changed);

	dev_info(ctrl->ctrl.device, "new ctrl: NQN \"%s\", addr %pISp\n",
		ctrl->ctrl.opts->subsysnqn, &ctrl->addr);

	kref_get(&ctrl->ctrl.kref);

	mutex_lock(&nvme_tcp_ctrl_mutex);
	list_add_tail(&ctrl->list, &nvme_tcp_ctrl_list);
	mutex_unlock(&nvme_tcp_ctrl_mutex);

	if (opts->nr_io_queues) {
		nvme_queue_scan(&ctrl->ctrl);
		nvme_queue_async_events(&ctrl->ctrl);
	}

	return &ctrl->ctrl;

out_remove_admin_queue:
	nvme_stop_keep_alive(&ctrl->ctrl);
	nvme_tcp_destroy_admin_queue(ctrl);
out_kfree_queues:
	kfree(ctrl->queues);
out_uninit_ctrl:
	nvme_uninit_ctrl(&ctrl->ctrl);
	nvme_put_ctrl(&ctrl->ctrl);
	if (ret > 0)
		ret = -EIO;
	return ERR_PTR(ret);
out_free_wq:
	destroy_workqueue(ctrl->workqueue);
out_free_ctrl:
	kfree(ctrl);
	return ERR_PTR(ret);
}

static struct nvmf_transport_ops nvme_tcp_transport = {
	.name		= "tcp",
	.required_opts	= NVMF_OPT_TRADDR,
	.allowed_opts	= NVMF_OPT_TRSVCID | NVMF_OPT_RECONNECT_DELAY,
	.create_ctrl	= nvme_tcp_create_ctrl,
};

static int __init nvme_tcp_init_module(void)
{
	nvmf_register_transport(&nvme_tcp_transport);
	return  0;
}

static void __exit nvme_tcp_cleanup_module(void)
{
	nvmf_unregister_transport(&nvme_tcp_transport);
}

module_init(nvme_tcp_init_module);
module_exit(nvme_tcp_cleanup_module);

MODULE_LICENSE("GPL v2");
