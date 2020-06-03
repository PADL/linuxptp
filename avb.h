/******************************************************************************

  Copyright (c) 2009-2012, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. Neither the name of the Intel Corporation nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

 ******************************************************************************/

#ifndef AVB_H
#define AVB_H

/**@file
 * This is a common header file. OS-specific implementations should use
 * this file as base. Currently we have two IPC implementations:
 * Linux: Located at linux/src/linux_ipc.hpp (among other files that include this)
 * Windows: Located at windows/daemon_cl/windows_ipc.hpp
*/

#include <stdbool.h>
#include "fsm.h"

struct avb_control_interface;

bool
avb_control_interface_init(void);

void
avb_control_interface_update(
    int64_t ml_phoffset,
    double ml_freqoffset,
    int64_t local_time,
    uint32_t sync_count);

void
avb_control_interface_update_clock(
    uint8_t clock_identity[],
    uint8_t priority1,
    uint8_t clock_class,
    int16_t offset_scaled_log_variance,
    uint8_t clock_accuracy,
    uint8_t priority2,
    uint8_t domain_number);

void
avb_control_interface_update_port(
    int8_t log_sync_interval,
    int8_t log_announce_interval,
    int8_t log_pdelay_interval,
    uint16_t port_number,
    uint32_t pdelay_count,
    enum port_state port_state,
    bool asCapable);

void
avb_control_interface_update_gm(
    uint8_t gptp_grandmaster_id[],
    uint8_t gptp_domain_number);

void
avb_control_interface_close(void);

#endif/*AVB_H*/
