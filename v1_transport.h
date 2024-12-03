/**
 * @file v1_transport.h
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2024 PADL Software Pty Ltd, Luke Howard <lukeh@padl.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_V1_TRANSPORT_H
#define HAVE_V1_TRANSPORT_H

/**
 * Allocate an instance of a UDP/IPv4 transport with PTPv1 translation.
 * @return Pointer to a new transport instance on success, NULL otherwise.
 */
struct transport *v1_udp_transport_create(void);

/**
 * Allocate an instance of a UDP/IPv6 transport with PTPv1 translation.
 * @return Pointer to a new transport instance on success, NULL otherwise.
 */
struct transport *v1_udp6_transport_create(void);

#endif
