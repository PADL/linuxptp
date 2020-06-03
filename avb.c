/**
 * @file avb.c
 * @brief Exports Intel gPTP daemon shared memory interface.
 * @note Copyright (C) 2020 Luke Howard <lukeh@padl.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "util.h"
#include "avb.h"

typedef enum {
    PTP_MASTER = 7,         //!< Port is PTP Master
    PTP_PRE_MASTER,         //!< Port is not PTP Master yet.
    PTP_SLAVE,                      //!< Port is PTP Slave
    PTP_UNCALIBRATED,       //!< Port is uncalibrated.
    PTP_DISABLED,           //!< Port is not PTP enabled. All messages are ignored when in this state.
    PTP_FAULTY,                     //!< Port is in a faulty state. Recovery is implementation specific.
    PTP_INITIALIZING,       //!< Port's initial state.
    PTP_LISTENING           //!< Port is in a PTP listening state. Currently not in use.
} port_state_t;

/**
 * @brief Provides a data structure for gPTP time
 */
typedef struct {
    int64_t ml_phoffset;			//!< Master to local phase offset
    int64_t ls_phoffset;			//!< Local to system phase offset
    long double ml_freqoffset;	//!< Master to local frequency offset
    long double ls_freqoffset;	//!< Local to system frequency offset
    uint64_t local_time;			//!< Local time of last update

    /* Current grandmaster information */
    /* Referenced by the IEEE Std 1722.1-2013 AVDECC Discovery Protocol Data Unit (ADPDU) */
    uint8_t gptp_grandmaster_id[8];	//!< Current grandmaster id (all 0's if no grandmaster selected)
    uint8_t gptp_domain_number;		//!< gPTP domain number

    /* Grandmaster support for the network interface */
    /* Referenced by the IEEE Std 1722.1-2013 AVDECC AVB_INTERFACE descriptor */
    uint8_t  clock_identity[8];	//!< The clock identity of the interface
    uint8_t  priority1;				//!< The priority1 field of the grandmaster functionality of the interface, or 0xFF if not supported
    uint8_t  clock_class;			//!< The clockClass field of the grandmaster functionality of the interface, or 0xFF if not supported
    int16_t  offset_scaled_log_variance;	//!< The offsetScaledLogVariance field of the grandmaster functionality of the interface, or 0x0000 if not supported
    uint8_t  clock_accuracy;		//!< The clockAccuracy field of the grandmaster functionality of the interface, or 0xFF if not supported
    uint8_t  priority2;				//!< The priority2 field of the grandmaster functionality of the interface, or 0xFF if not supported
    uint8_t  domain_number;			//!< The domainNumber field of the grandmaster functionality of the interface, or 0 if not supported
    int8_t   log_sync_interval;		//!< The currentLogSyncInterval field of the grandmaster functionality of the interface, or 0 if not supported
    int8_t   log_announce_interval;	//!< The currentLogAnnounceInterval field of the grandmaster functionality of the interface, or 0 if not supported
    int8_t   log_pdelay_interval;	//!< The currentLogPDelayReqInterval field of the grandmaster functionality of the interface, or 0 if not supported
    uint16_t port_number;			//!< The portNumber field of the interface, or 0x0000 if not supported

    /* Linux-specific */
    uint32_t sync_count;			//!< Sync messages count
    uint32_t pdelay_count;			//!< pdelay messages count
    bool asCapable;                 //!< asCapable flag: true = device is AS Capable; false otherwise
    port_state_t port_state;			//!< gPTP port state. It can assume values defined at ::PortState
    pid_t process_id;			//!< Process id number
} gptp_time_data_t;

#define PTP_SHM_NAME "/ptp"
#define PTP_SHM_SIZE (sizeof(pthread_mutex_t) + sizeof(gptp_time_data_t))

static uint8_t *gAvb;
#define GPTP_TIME_DATA(buffer)	((gptp_time_data_t *)(gAvb + sizeof(pthread_mutex_t)))

bool
avb_control_interface_init(void)
{
    int fd;
    pthread_mutexattr_t attr;
    gptp_time_data_t *td;

    fd = shm_open(PTP_SHM_NAME, O_RDWR | O_CREAT, 0660);
    if (fd < 0){
	return false;
    }

    if (ftruncate(fd, PTP_SHM_SIZE) < 0) {
	close(fd);
	return false;
    }

    gAvb = mmap(NULL, PTP_SHM_SIZE, PROT_READ | PROT_WRITE,
	        MAP_LOCKED | MAP_SHARED, fd, 0);
    if (gAvb == MAP_FAILED) {
	close(fd);
	return false;
    }

    close(fd);

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, 1);

    if (pthread_mutex_init((pthread_mutex_t *)gAvb, &attr) != 0) {
	avb_control_interface_close();
	return false;
    }

    td = GPTP_TIME_DATA(gAvb);
    memset(td, 0, sizeof(*td));
    td->process_id = getpid();

    return true;
}

void
avb_control_interface_close(void)
{
    munmap(gAvb, PTP_SHM_SIZE);
    shm_unlink(PTP_SHM_NAME);
}

void
avb_control_interface_update_port(
    int8_t log_sync_interval,
    int8_t log_announce_interval,
    int8_t log_pdelay_interval,
    uint16_t port_number,
    uint32_t pdelay_count,
    enum port_state port_state,
    bool asCapable)
{
    gptp_time_data_t *td = GPTP_TIME_DATA(gAvb);

    pthread_mutex_lock((pthread_mutex_t *)gAvb);
    td->log_sync_interval = log_sync_interval;
    td->log_announce_interval = log_announce_interval;
    td->log_pdelay_interval = log_pdelay_interval;
    td->port_number = port_number;
    td->pdelay_count = pdelay_count;
    switch (port_state) {
    case PS_INITIALIZING:
	td->port_state = PTP_INITIALIZING;
	break;
    case PS_FAULTY:
	td->port_state = PTP_FAULTY;
	break;
    case PS_DISABLED:
	td->port_state = PTP_DISABLED;
	break;
    case PS_LISTENING:
	td->port_state = PTP_LISTENING;
	break;
    case PS_PRE_MASTER:
	td->port_state = PTP_PRE_MASTER;
	break;
    case PS_MASTER:
	td->port_state = PTP_MASTER;
	break;
    case PS_UNCALIBRATED:
	td->port_state = PTP_UNCALIBRATED;
	break;
    case PS_SLAVE:
	td->port_state = PTP_SLAVE;
	break;
    case PS_PASSIVE:
    case PS_GRAND_MASTER:
    default:
	td->port_state = 0;
	break;
    }
    td->asCapable = asCapable;
    pthread_mutex_unlock((pthread_mutex_t *)gAvb);
}

void
avb_control_interface_update_clock(
    uint8_t clock_identity[],
    uint8_t priority1,
    uint8_t clock_class,
    int16_t offset_scaled_log_variance,
    uint8_t clock_accuracy,
    uint8_t priority2,
    uint8_t domain_number)
{
    gptp_time_data_t *td = GPTP_TIME_DATA(gAvb);

    pthread_mutex_lock((pthread_mutex_t *)gAvb);
    memcpy(td->clock_identity, clock_identity, sizeof(td->clock_identity));
    td->priority1 = priority1;
    td->clock_class = clock_class;
    td->offset_scaled_log_variance = offset_scaled_log_variance;
    td->clock_accuracy = clock_accuracy;
    td->priority2 = priority2;
    td->domain_number = domain_number;
    pthread_mutex_unlock((pthread_mutex_t *)gAvb);
}

void
avb_control_interface_update(
    int64_t ml_phoffset,
    //int64_t ls_phoffset,
    double ml_freqoffset,
    //double ls_freqoffset,
    int64_t local_time,
    uint32_t sync_count)
{
    gptp_time_data_t *td = GPTP_TIME_DATA(gAvb);

    pthread_mutex_lock((pthread_mutex_t *)gAvb);
    td->ml_phoffset = ml_phoffset;
    //td->ls_phoffset = ls_phoffset;
    td->ml_freqoffset = ml_freqoffset;
    //td->ls_freqoffset = ls_freqoffset;
    td->local_time = local_time;
    td->sync_count = sync_count;
    pthread_mutex_unlock((pthread_mutex_t *)gAvb);
}

void
avb_control_interface_update_gm(
    uint8_t gptp_grandmaster_id[],
    uint8_t gptp_domain_number)
{
    gptp_time_data_t *td = GPTP_TIME_DATA(gAvb);

    pthread_mutex_lock((pthread_mutex_t *)gAvb);
    memcpy(td->gptp_grandmaster_id,
	   gptp_grandmaster_id, sizeof(td->gptp_grandmaster_id));
    td->gptp_domain_number = gptp_domain_number;
    pthread_mutex_unlock((pthread_mutex_t *)gAvb);
}

