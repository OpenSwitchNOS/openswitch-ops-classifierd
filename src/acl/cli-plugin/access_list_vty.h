/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/************************************************************************//**
 * @defgroup ops-access-list Access Control List (ACL)
 * Access Control List (ACL) CLI commands and associated code.
 * See ops/doc/access_list_cli.md for command syntax/documentation.
 ***************************************************************************/

/************************************************************************//**
 * @ingroup ops-access-list
 *
 * @file
 * Definition of Access Control List (ACL) CLI functions
 ***************************************************************************/

#ifndef _ACCESS_LIST_VTY_H
#define _ACCESS_LIST_VTY_H

/** Standard CLI entry point for first stage of initalization */
void cli_pre_init(void);

/** Standard CLI entry point for second stage of initalization */
void cli_post_init(void);

#endif /* _ACCESS_LIST_VTY_H */
