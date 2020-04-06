// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Nitro Enclaves (NE) PCI device driver. */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/nitro_enclaves.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "ne_main.h"

/* TODO: Motivate magic numbers. */

/* Number of milliseconds to wait before polling the PCI device for a reply. */
#define HRTIMER_POLL_MS	(5)

/* Maximum amount of seconds before the hrtimer is stopped. */
#define HRTIMER_MAX_TIME (45)

static const struct pci_device_id ne_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMAZON, PCI_DEVICE_ID_NE) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, ne_pci_ids);

static int validate_request(struct pci_dev *pdev, struct ne_pci_dev *ne_pci_dev,
			    enum ne_pci_dev_cmd_type cmd_type,
			    void *cmd_request, size_t cmd_request_size)
{
	if (!ne_pci_dev) {
		pr_err("NULL ne_pci_dev\n");

		return -EINVAL;
	}

	if (!ne_pci_dev->iomem_base) {
		pr_err("NULL iomem_base\n");

		return -EINVAL;
	}

	if ((cmd_type <= INVALID_CMD) || (cmd_type >= MAX_CMD)) {
		pr_err("Invalid cmd_type=%d\n", cmd_type);

		return -EINVAL;
	}

	if (!cmd_request) {
		pr_err("NULL cmd_request\n");

		return -EINVAL;
	}

	if (cmd_request_size > NE_SEND_DATA_SIZE) {
		pr_err("Invalid cmd_request_size=%ld for cmd_type=%d\n",
		       cmd_request_size, cmd_type);

		return -EINVAL;
	}

	return 0;
}

/**
 * submit_request - Submit command request to the PCI device based on the
 * command type.
 *
 * This function gets called with the ne_pci_dev lock held.
 *
 * @pdev: PCI device to send the command to.
 * @cmd_type: command type of the request sent to the PCI device.
 * @cmd_request: command request payload.
 * @cmd_request_size: size of the command request payload.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int submit_request(struct pci_dev *pdev,
			  enum ne_pci_dev_cmd_type cmd_type, void *cmd_request,
			  size_t cmd_request_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int rc = -EINVAL;

	rc = validate_request(pdev, ne_pci_dev, cmd_type, cmd_request,
			      cmd_request_size);
	if (rc < 0) {
		pr_err("Invalid request [rc=%d]\n", rc);

		return rc;
	}

	memcpy_toio(ne_pci_dev->iomem_base + NE_REG_SEND_DATA, cmd_request,
		    cmd_request_size);

	iowrite32(cmd_type, ne_pci_dev->iomem_base + NE_REG_COMMAND);

	return 0;
}

static int validate_reply(struct pci_dev *pdev, struct ne_pci_dev *ne_pci_dev,
			  void *cmd_reply, size_t cmd_reply_size)
{
	if (!ne_pci_dev) {
		pr_err("NULL ne_pci_dev\n");

		return -EINVAL;
	}

	if (!ne_pci_dev->iomem_base) {
		pr_err("NULL iomem_base\n");

		return -EINVAL;
	}

	if (!cmd_reply) {
		pr_err("NULL cmd_reply\n");

		return -EINVAL;
	}

	if (cmd_reply_size > NE_RECV_DATA_SIZE) {
		pr_err("Invalid cmd_reply_size=%ld\n", cmd_reply_size);

		return -EINVAL;
	}

	return 0;
}

/**
 * retrieve_reply - Retrieve reply from the PCI device.
 *
 * This function gets called with the ne_pci_dev lock held.
 *
 * @pdev: PCI device to receive the reply from.
 * @cmd_reply: command reply payload.
 * @cmd_reply_size: size of the command reply payload.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int retrieve_reply(struct pci_dev *pdev,
			  struct ne_pci_dev_cmd_reply *cmd_reply,
			  size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int rc = -EINVAL;

	rc = validate_reply(pdev, ne_pci_dev, cmd_reply, cmd_reply_size);
	if (rc < 0) {
		pr_err("Invalid reply [rc=%d]\n", rc);

		return rc;
	}

	memcpy_fromio(cmd_reply, ne_pci_dev->iomem_base + NE_REG_RECV_DATA,
		      cmd_reply_size);

	return 0;
}

/**
 * poll_pci_reply - Callback hrtimer handler for polling the PCI device
 * until a reply is received. A reply is considered received if the value
 * of the @ref NE_REG_REPLY_PENDING register changes after submitting the
 * PCI command.
 *
 * @hrtimer: timer used for polling the PCI device.
 *
 * @returns: HRTIMER_RESTART on reply not being retried, HRTIMER_NORESTART
 *	     on retrieving a reply or reaching the maximum number of retries.
 */
static enum hrtimer_restart poll_pci_reply(struct hrtimer *hrtimer)
{
	ktime_t actual_time = {0};
	struct ne_pci_poll *poll =
		container_of(hrtimer, struct ne_pci_poll, timer);
	struct ne_pci_dev *ne_pci_dev =
		container_of(poll, struct ne_pci_dev, poll);
	u32 reply = 0;

	actual_time = hrtimer_cb_get_time(&poll->timer);

	/* Nitro Hypervisor failed to offer a reply. */
	BUG_ON(ktime_compare(actual_time, poll->end_time) >= 0);

	reply = ioread32(ne_pci_dev->iomem_base + NE_REG_REPLY_PENDING) &
		REPLY_MASK;

	/* No reply received. */
	if (poll->prev_reply == reply) {
		/* Reset the timer for further polling. */
		hrtimer_forward_now(hrtimer, ms_to_ktime(HRTIMER_POLL_MS));

		return HRTIMER_RESTART;
	}

	poll->recv_reply = true;

	/* TODO: Update to _interruptible. */
	wake_up(&poll->reply_q);

	return HRTIMER_NORESTART;
}

/**
 * wait_for_reply - Wait for a reply of a PCI command.
 *
 * This function gets called with the ne_pci_dev lock held.
 *
 * @pdev: PCI device for which a reply is waited.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int wait_for_reply(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	if (!ne_pci_dev)
		return -EINVAL;

	/* Handle reply with MSI-X. */
	if (pdev->msix_enabled) {
		/*
		 * TODO: Update to _interruptible and handle interrupted wait
		 * event e.g. -ERESTARTSYS, incoming signals + add timeout.
		 */
		wait_event(ne_pci_dev->cmd_reply_wait_q,
			   ne_pci_dev->cmd_reply_available);

		ne_pci_dev->cmd_reply_available = false;

		return 0;
	}

	/* Compute the end time after which the hrtimer is stopped. */
	ne_pci_dev->poll.end_time =
		ktime_add(hrtimer_cb_get_time(&ne_pci_dev->poll.timer),
			  ktime_set(HRTIMER_MAX_TIME, 0));

	ne_pci_dev->poll.recv_reply = false;

	/* Trigger timer immediately to check for enclave state. */
	hrtimer_start(&ne_pci_dev->poll.timer, ms_to_ktime(0),
		      HRTIMER_MODE_REL);

	/*
	 * TODO: Update to _interruptible and handle interrupted wait
	 * event e.g. -ERESTARTSYS, incoming signals + add timeout.
	 */
	wait_event(ne_pci_dev->poll.reply_q, ne_pci_dev->poll.recv_reply);

	return 0;
}

/**
 * do_request - Submit command request to the PCI device based on the command
 * type and retrieve the associated reply.
 *
 * This function uses the ne_pci_dev lock to handle one command at a time.
 *
 * @pdev: PCI device to send the command to and receive the reply from.
 * @cmd_type: command type of the request sent to the PCI device.
 * @cmd_request: command request payload.
 * @cmd_request_size: size of the command request payload.
 * @cmd_reply: command reply payload.
 * @cmd_reply_size: size of the command reply payload.
 *
 * @returns: 0 on success, negative return value on failure.
 */
int do_request(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
	       void *cmd_request, size_t cmd_request_size,
	       struct ne_pci_dev_cmd_reply *cmd_reply, size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);
	int rc = -EINVAL;

	rc = validate_request(pdev, ne_pci_dev, cmd_type, cmd_request,
			      cmd_request_size);
	if (rc < 0) {
		pr_err("Invalid request [rc=%d]\n", rc);

		return rc;
	}

	rc = validate_reply(pdev, ne_pci_dev, cmd_reply, cmd_reply_size);
	if (rc < 0) {
		pr_err("Invalid reply [rc=%d]\n", rc);

		return rc;
	}

	mutex_lock(&ne_pci_dev->pci_dev_lock);

	if (!pdev->msix_enabled)
		ne_pci_dev->poll.prev_reply =
			ioread32(ne_pci_dev->iomem_base +
				 NE_REG_REPLY_PENDING) & REPLY_MASK;

	rc = submit_request(pdev, cmd_type, cmd_request, cmd_request_size);
	if (rc < 0) {
		pr_err("Failure in pci dev submit request [rc=%d]\n", rc);

		mutex_unlock(&ne_pci_dev->pci_dev_lock);

		return rc;
	}

	rc = wait_for_reply(pdev);
	if (rc < 0) {
		pr_err("Failure in pci wait for reply [rc=%d]\n", rc);

		mutex_unlock(&ne_pci_dev->pci_dev_lock);

		return rc;
	}

	rc = retrieve_reply(pdev, cmd_reply, cmd_reply_size);
	if (rc < 0) {
		pr_err("Failure in pci dev retrieve reply [rc=%d]\n", rc);

		mutex_unlock(&ne_pci_dev->pci_dev_lock);

		return rc;
	}

	if (cmd_reply->rc < 0) {
		pr_err("Failure in the device command process logic [rc=%d]\n",
		       cmd_reply->rc);

		mutex_unlock(&ne_pci_dev->pci_dev_lock);

		return cmd_reply->rc;
	}

	mutex_unlock(&ne_pci_dev->pci_dev_lock);

	return 0;
}

/**
 * ne_pci_dev_comm_handler - Interrupt handler for retrieving a reply matching
 * a request sent to the PCI device for enclave lifetime management.
 *
 * @irq: received interrupt for a reply sent by the PCI device.
 * @args: PCI device private data structure.
 *
 * @returns: IRQ_HANDLED on handled interrupt, IRQ_NONE otherwise.
 */
static irqreturn_t ne_pci_dev_comm_handler(int irq, void *args)
{
	struct ne_pci_dev *ne_pci_dev = (struct ne_pci_dev *) args;

	ne_pci_dev->cmd_reply_available = true;

	/* TODO: Update to _interruptible. */
	wake_up(&ne_pci_dev->cmd_reply_wait_q);

	return IRQ_HANDLED;
}

/**
 * ne_rescan_work_handler - Work queue handler for notifying enclaves on
 * a state change received by the interrupt handler @ref
 * ne_pci_dev_rescan_hndlr.
 *
 * A rescan event is being issued by the Nitro Hypervisor when at least
 * one enclave is changing state without client interaction.
 *
 * @work: item containing the Nitro Enclaves PCI device for which a
 *	  rescan event was issued.
 */
static void ne_rescan_work_handler(struct work_struct *work)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct ne_enclave *ne_enclave = NULL;
	struct ne_pci_dev *ne_pci_dev =
		container_of(work, struct ne_pci_dev, notify_work);
	int rc = -EINVAL;
	struct slot_info_req slot_info_req = {};

	mutex_lock(&ne_pci_dev->enclaves_list_lock);

	/*
	 * Iterate over all enclaves registered for the Nitro Enclaves
	 * PCI device and determine for which enclave(s) the rescan event
	 * is corresponding to.
	 */
	list_for_each_entry(ne_enclave, &ne_pci_dev->enclaves_list,
			    enclave_list_entry) {
		mutex_lock(&ne_enclave->lock);

		/*
		 * Enclaves that were never started cannot receive
		 * rescan events.
		 */
		if (ne_enclave->state != NE_STATE_RUNNING)
			goto unlock;

		slot_info_req.slot_uid = ne_enclave->slot_uid;

		rc = do_request(ne_enclave->pdev, SLOT_INFO, &slot_info_req,
				sizeof(slot_info_req), &cmd_reply,
				sizeof(cmd_reply));
		/* Slot info is not supposed to fail for an active slot. */
		BUG_ON(rc);

		/* Notify enclave process that the enclave state changed. */
		if (ne_enclave->state != cmd_reply.state) {
			ne_enclave->state = cmd_reply.state;

			ne_enclave->has_event = true;

			wake_up_interruptible(&ne_enclave->eventq);
		}

unlock:
		 mutex_unlock(&ne_enclave->lock);
	}

	mutex_unlock(&ne_pci_dev->enclaves_list_lock);
}

/**
 * ne_pci_dev_rescan_handler - Interrupt handler for PCI device rescan
 * events. This interrupt does not supply any data in the MMIO region.
 * It notifies a change in the state of any of the launched enclaves.
 *
 * @irq: received interrupt for an rescan event.
 * @args: PCI device private data structure.
 *
 * @returns: IRQ_HANDLED on handled interrupt, IRQ_NONE otherwise.
 */
static irqreturn_t ne_pci_dev_rescan_handler(int irq, void *args)
{
	struct ne_pci_dev *ne_pci_dev = (struct ne_pci_dev *) args;

	queue_work(ne_pci_dev->event_wq, &ne_pci_dev->notify_work);

	return IRQ_HANDLED;
}

/**
 * ne_pci_dev_setup_msix - Setup MSI-X vectors for the PCI device.
 *
 * @pdev: PCI device to setup the MSI-X for.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_pci_dev_setup_msix(struct pci_dev *pdev,
				 struct ne_pci_dev *ne_pci_dev)
{
	int nr_vecs = 0;
	int rc = -EINVAL;

	if (!ne_pci_dev)
		return -EINVAL;

	nr_vecs = pci_msix_vec_count(pdev);
	if (nr_vecs < 0) {
		rc = nr_vecs;

		dev_err(&pdev->dev,
			"Failure in getting MSI-X vector count [rc=%d]\n", rc);

		/* Setup fallback polling mechanism: hrtimer. */
		hrtimer_init(&ne_pci_dev->poll.timer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_REL);
		ne_pci_dev->poll.timer.function = poll_pci_reply;
		init_waitqueue_head(&ne_pci_dev->poll.reply_q);
		pdev->msix_enabled = 0;

		return 0;
	}

	ne_pci_dev->event_wq = create_singlethread_workqueue("ne_pci_dev_wq");
	if (!ne_pci_dev->event_wq) {
		rc = -ENOMEM;

		dev_err(&pdev->dev,
		       "Cannot create workqueue for rescan events [rc=%d]\n",
		       rc);

		goto err_create_wq;
	}

	INIT_WORK(&ne_pci_dev->notify_work, ne_rescan_work_handler);

	rc = pci_alloc_irq_vectors(pdev, nr_vecs, nr_vecs, PCI_IRQ_MSIX);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Failure in allocating MSI-X vectors [rc=%d]\n", rc);

		goto err_alloc_irq_vecs;
	}

	/*
	 * Request an IRQ that shall be asserted either each time
	 * the device responds to a command. The MMIO protocol
	 * protocol is handled once the interrupt has been received.
	 */
	rc = request_irq(pci_irq_vector(pdev, NE_VEC_COMM),
			 ne_pci_dev_comm_handler, 0, "enclave_cmd", ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Failure in allocating irq comm [rc=%d]\n",
			rc);

		goto err_req_irq_comm;
	}

	/*
	 * Request an IRQ that shall be asserted either each time
	 * an enclave related event takes place in the device. The
	 * enclaves info, including state, scanning is handled in the
	 * interrupt handler.
	 */
	rc = request_irq(pci_irq_vector(pdev, NE_VEC_RESCAN),
			 ne_pci_dev_rescan_handler, 0, "enclave_evt",
			 ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Failure in allocating irq rescan [rc=%d]\n", rc);

		goto err_req_irq_rescan;
	}

	return 0;

err_req_irq_rescan:
	free_irq(pci_irq_vector(pdev, NE_VEC_COMM), ne_pci_dev);
err_req_irq_comm:
	pci_free_irq_vectors(pdev);
err_alloc_irq_vecs:
	destroy_workqueue(ne_pci_dev->event_wq);
err_create_wq:
	return rc;
}

/**
 * ne_pci_dev_enable - Select PCI device version and enable it.
 *
 * @pdev: PCI device to select version for and then enable.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_pci_dev_enable(struct pci_dev *pdev,
			     struct ne_pci_dev *ne_pci_dev)
{
	u8 dev_enable_reply = 0;
	u16 dev_version_reply = 0;
	int rc = -EINVAL;

	if (!ne_pci_dev || !ne_pci_dev->iomem_base)
		return -EINVAL;

	iowrite16(DEV_VERSION, ne_pci_dev->iomem_base + NE_REG_VERSION);

	dev_version_reply = ioread16(ne_pci_dev->iomem_base + NE_REG_VERSION);
	if ((dev_version_reply & DEV_VERSION_MASK) != DEV_VERSION) {
		rc = -EIO;

		dev_err(&pdev->dev,
			"Failure in pci dev version cmd [rc=%d]\n",
			rc);

		return rc;
	}

	iowrite8(DEV_ENABLE, ne_pci_dev->iomem_base + NE_REG_ENABLE);

	dev_enable_reply = ioread8(ne_pci_dev->iomem_base + NE_REG_ENABLE);
	if ((dev_enable_reply & DEV_ENABLE_MASK) != DEV_ENABLE) {
		rc = -EIO;

		dev_err(&pdev->dev,
			"Failure in pci dev enable cmd [rc=%d]\n", rc);

		return rc;
	}

	return 0;
}

static int ne_pci_dev_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;

	ne_pci_dev = kzalloc(sizeof(*ne_pci_dev), GFP_KERNEL);
	if (!ne_pci_dev)
		return -ENOMEM;

	rc = pci_enable_device(pdev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Failure in pci dev enable [rc=%d]\n", rc);

		goto err_pci_enable_dev;
	}

	rc = pci_request_regions(pdev, "ne_pci_dev");
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Failure in pci request regions [rc=%d]\n", rc);

		goto err_req_regions;
	}

	ne_pci_dev->iomem_base = pci_iomap(pdev, PCI_BAR_NE, 0);
	if (!ne_pci_dev->iomem_base) {
		rc = -ENOMEM;

		dev_err(&pdev->dev, "Failure in pci bar mapping [rc=%d]\n", rc);

		goto err_iomap;
	}

	rc = ne_pci_dev_setup_msix(pdev, ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Failure in pci dev msix setup [rc=%d]\n",
			rc);

		goto err_setup_msix;
	}

	rc = ne_pci_dev_enable(pdev, ne_pci_dev);
	if (rc < 0) {
		dev_err(&pdev->dev, "Failure in ne_pci_dev enable [rc=%d]\n",
			rc);

		goto err_ne_pci_dev_enable;
	}

	ne_pci_dev->cmd_reply_available = false;
	init_waitqueue_head(&ne_pci_dev->cmd_reply_wait_q);
	INIT_LIST_HEAD(&ne_pci_dev->enclaves_list);
	mutex_init(&ne_pci_dev->enclaves_list_lock);
	mutex_init(&ne_pci_dev->pci_dev_lock);

	pci_set_drvdata(pdev, ne_pci_dev);

	return 0;

err_ne_pci_dev_enable:
	free_irq(pci_irq_vector(pdev, NE_VEC_RESCAN), ne_pci_dev);
	free_irq(pci_irq_vector(pdev, NE_VEC_COMM), ne_pci_dev);
	pci_free_irq_vectors(pdev);
err_setup_msix:
	pci_iounmap(pdev, ne_pci_dev->iomem_base);
	ne_pci_dev->iomem_base = NULL;
err_iomap:
	pci_release_regions(pdev);
err_req_regions:
	pci_disable_device(pdev);
err_pci_enable_dev:
	kfree(ne_pci_dev);
	ne_pci_dev = NULL;
	return rc;
}

/**
 * ne_pci_dev_disable - Disable PCI device.
 *
 * @pdev: PCI device to disable.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static void ne_pci_dev_disable(struct pci_dev *pdev,
			       struct ne_pci_dev *ne_pci_dev)
{
	u8 dev_disable_reply = 0;
	int rc = -EINVAL;

	if (!ne_pci_dev || !ne_pci_dev->iomem_base)
		return;

	iowrite8(DEV_DISABLE, ne_pci_dev->iomem_base + NE_REG_ENABLE);

	dev_disable_reply = ioread8(ne_pci_dev->iomem_base + NE_REG_ENABLE);
	if ((dev_disable_reply & DEV_ENABLE_MASK) != DEV_DISABLE) {
		rc = -EIO;

		dev_err(&pdev->dev,
			"Failure in pci dev disable cmd [rc=%d]\n", rc);
	}
}

static void ne_pci_dev_remove(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	if (!ne_pci_dev || !ne_pci_dev->iomem_base)
		return;

	ne_pci_dev_disable(pdev, ne_pci_dev);

	pci_set_drvdata(pdev, NULL);

	if (pdev->msix_enabled) {
		free_irq(pci_irq_vector(pdev, NE_VEC_COMM), ne_pci_dev);
		free_irq(pci_irq_vector(pdev, NE_VEC_RESCAN), ne_pci_dev);
		pci_free_irq_vectors(pdev);
	} else {
		hrtimer_cancel(&ne_pci_dev->poll.timer);
	}

	if (ne_pci_dev->event_wq) {
		flush_workqueue(ne_pci_dev->event_wq);
		destroy_workqueue(ne_pci_dev->event_wq);
		memset(&ne_pci_dev->notify_work, 0,
		       sizeof(ne_pci_dev->notify_work));
	}

	pci_iounmap(pdev, ne_pci_dev->iomem_base);
	ne_pci_dev->iomem_base = NULL;

	kfree(ne_pci_dev);
	ne_pci_dev = NULL;

	pci_release_regions(pdev);

	pci_disable_device(pdev);
}

/*
 * TODO: Add suspend / resume functions for power management w/ CONFIG_PM, if
 * needed.
 */
static struct pci_driver ne_pci_driver = {
	.name		= "ne_pci_dev",
	.id_table	= ne_pci_ids,
	.probe		= ne_pci_dev_probe,
	.remove		= ne_pci_dev_remove,
};

struct pci_dev *ne_get_pci_dev(void)
{
	return pci_get_device(PCI_VENDOR_ID_AMAZON, PCI_DEVICE_ID_NE, NULL);
}

int ne_pci_dev_init(void)
{
	return pci_register_driver(&ne_pci_driver);
}

void ne_pci_dev_uninit(void)
{
	pci_unregister_driver(&ne_pci_driver);
}
