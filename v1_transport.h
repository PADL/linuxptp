/**
 * @file v1.h
 * @brief Implements the IEEE1588-2002 PTP message types.
 * @note Copyright (C) 2024 PADL Software Pty Ltd, Luke Howard <lukeh@padl.com>
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
