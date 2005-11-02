/*
 * This file is part of the original implementation of the lockbox API for the
 * Linux kernel.
 *
 * Copyright 2005 Troy Rollo
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define	LKB_ALLOCATION_UNIT	128

typedef struct lockbox_box_
{
	struct 	lockbox_box_ *lkb_b_next;	/* link to the next lock box	*/
	char		*lkb_b_name;		/* name of this lock box	*/
	struct file	*lkb_b_file;		/* file stored in the lock box	*/
	lockbox_acl	*lkb_b_acl;		/* Access control list		*/
	char		*lkb_b_data;		/* Data				*/
	uint32_t	lkb_b_size;		/* Size of data			*/
	uint32_t	lkb_b_users;		/* Number of users		*/
	uint32_t	lkb_b_holders;		/* Still need the pointer	*/
	uint32_t	lkb_b_userlocks;	/* User level lock bits 	*/
	uint32_t	lkb_b_state;		/* State bits			*/
	uint32_t	lkb_b_shelf;		/* The shelf we are on		*/
	struct 		semaphore lkb_b_lock;	/* Exclusive access control	*/
	wait_queue_head_t lkb_b_waitq;
} lockbox_box;

typedef struct
{
	lockbox_box	*lkb_bu_box;
	uint32_t	lkb_bu_select_users_lt;
	uint32_t	lkb_bu_select_users_gt;
	uint32_t	lkb_bu_select_flags;
	uint32_t	lkb_bu_select_wantlock;
	uint32_t	lkb_bu_locks_held;
} lockbox_boxuse;

typedef struct
{
	lockbox_box	*lkb_s_boxlist;
	uint32_t	lkb_s_seqno;
	struct semaphore lkb_s_lock;
} lockbox_shelf;

#define IN_SHELFLIST_SHELVES ((LKB_ALLOCATION_UNIT - sizeof(void *)) / sizeof(lockbox_shelf))

typedef struct lockbox_shelflist_
{
	struct lockbox_shelflist_ *lkb_sl_next;
	lockbox_shelf lkb_sl_shelves[IN_SHELFLIST_SHELVES];
} lockbox_shelflist;

#define	IN_VAULT_SHELVES ((LKB_ALLOCATION_UNIT - \
			   sizeof(struct semaphore) - \
			   sizeof(void *) * 3 - \
			   sizeof(uint32_t)) / sizeof(lockbox_shelf))
typedef struct lockbox_vault_
{
	struct	lockbox_vault_ *lkb_v_next;
	char	*lkb_v_name;
	uint32_t lkb_v_users;

	/* Use the lock below when modifying the shelf list
	 */
	lockbox_shelflist *lkb_v_shelflist;
	struct	semaphore lkb_v_lock;
	lockbox_shelf lkb_v_shelves[IN_VAULT_SHELVES];
} lockbox_vault;

#define	IN_BOXLIST_BOXES ((LKB_ALLOCATION_UNIT - \
			   sizeof(void *)) / sizeof(lockbox_boxuse))
typedef struct lockbox_boxlist_
{
	struct lockbox_boxlist_ *lkb_bl_next;
	lockbox_boxuse	lkb_bl_boxes[IN_BOXLIST_BOXES];
} lockbox_boxlist;

#define	IN_PERFILE_BOXES ((LKB_ALLOCATION_UNIT - \
			   sizeof(struct semaphore) - \
			   sizeof(void *) * 2) / sizeof(lockbox_boxuse))
typedef struct
{
	struct	semaphore lkb_pf_lock;
	lockbox_vault *lkb_pf_vault;
	lockbox_boxlist *lkb_pf_boxlist;
	lockbox_boxuse	lkb_pf_boxes[IN_PERFILE_BOXES];
} lockbox_perfile;

