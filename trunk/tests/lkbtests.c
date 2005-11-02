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

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include "lockbox.h"

static int	status = 0;

#define EQ_OK(x, y) if ((x) != y) { fprintf(stderr, "Test failed at line %d: %s != %s\n", __LINE__, #x, #y); status = 1; };
#define NE_OK(x, y) if ((x) == y) { fprintf(stderr, "Test failed at line %d: %s == %s\n", __LINE__, #x, #y); status = 1; };
#define GE_OK(x, y) if ((x) < y) { fprintf(stderr, "Test failed at line %d: %s < %s\n", __LINE__, #x, #y); status = 1; };
#define LE_OK(x, y) if ((x) > y) { fprintf(stderr, "Test failed at line %d: %s > %s\n", __LINE__, #x, #y); status = 1; };
#define S_OK(x, y) if (strcmp((x) , y)) { fprintf(stderr, "Test failed at line %d: %s != %s\n", __LINE__, #x, y); status = 1; };
#define S_NE_OK(x, y) if (!strcmp((x) , y)) { fprintf(stderr, "Test failed at line %d: %s == %s\n", __LINE__, #x, y); status = 1; };


void
alarm_handler(int i)
{
}

int
main(int argc, char **argv)
{
	char	vaultname[40];
	char	buffer[40];
	int	fdVault;
	int	fdFile;
	int	lb;
	int	lb2;
	lockbox_acl *acl;
	lockbox_acl *aclout;
	lockbox_acl *aclout2;
	uint32_t state;

	signal(SIGALRM, alarm_handler);
	sprintf(vaultname, "testvault_%d", getpid());

	NE_OK(acl = (lockbox_acl *) malloc(LKB_ACL_SIZE(20)), 0);
	NE_OK(aclout = (lockbox_acl *) malloc(LKB_ACL_SIZE(20)), 0);
	NE_OK(aclout2 = (lockbox_acl *) malloc(LKB_ACL_SIZE(20)), 0);
	GE_OK(fdVault = lkb_openvault(vaultname), 0);

	if (status)
		return status;

	memset(acl, 0, LKB_ACL_SIZE(20));

	acl->la_header.lah_version = LKB_ACL_VERSION;
	acl->la_header.lah_n_entries = 2;

	acl->la_entries[0].lae_idtype = LKB_IDTYPE_USER;
	acl->la_entries[0].lae_id = geteuid();
	acl->la_entries[0].lae_access = 0;

	acl->la_entries[1].lae_idtype = LKB_IDTYPE_PROCESS;
	acl->la_entries[1].lae_id = getpid();
	acl->la_entries[1].lae_access = LKB_ACCESS_SETACL;

	NE_OK(lb = lkb_create(0, "test-box-1", "abcdef", 6, acl), LOCKBOX_ERROR);
	if (lb != LOCKBOX_ERROR)
	{
		size_t	sizeneeded = -1;

		LE_OK(lkb_getname(lb, buffer, 0, &sizeneeded), -1);
		EQ_OK(errno, ENOMEM);
		EQ_OK(sizeneeded, 11);

		GE_OK(lkb_getname(lb, buffer, 11, &sizeneeded), 0);
		S_OK(buffer, "test-box-1");

		EQ_OK(lkb_getusers(lb), 1);

		LE_OK(lkb_size(lb), -1);
		EQ_OK(errno, EPERM);

		LE_OK(lkb_getdata(lb, buffer, 0, 0), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_READ;
		GE_OK(lkb_setacl(lb, acl), 0);

		EQ_OK(lkb_size(lb), 6);

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 6, 0), 6);
		S_OK(buffer, "abcdef");

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 7,  0), 6);
		S_OK(buffer, "abcdef");

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 7, 1), 5);
		S_OK(buffer, "bcdef");

		LE_OK(lkb_setdata(lb, "uvwxyz", 6, 3), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_WRITE;
		GE_OK(lkb_setacl(lb, acl), 0);

		EQ_OK(lkb_setdata(lb, "uvwxyz", 6, 3), 6);
		EQ_OK(lkb_size(lb), 9);

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 10, 0), 9);
		S_OK(buffer, "abcuvwxyz");

		EQ_OK(lkb_setdata(lb, "mno", 3, 20), 3);
		EQ_OK(lkb_size(lb), 23);

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 3, 20), 3);
		S_OK(buffer, "mno");

		memset(buffer, 0, sizeof(buffer));
		EQ_OK(lkb_getdata(lb, buffer, 15, 0), 15);
		S_OK(buffer, "abcuvwxyz");

		LE_OK(lkb_getstate(lb, &state), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_GETSTATE;
		GE_OK(lkb_setacl(lb, acl), 0);

		GE_OK(lkb_getstate(lb, &state), 0);
		EQ_OK(state, 0);

		LE_OK(lkb_setstate(lb, 0x5a5a5a5a), -1);
		EQ_OK(errno, EPERM);

		GE_OK(lkb_getstate(lb, &state), 0);
		EQ_OK(state, 0);

		acl->la_entries[0].lae_access |= LKB_ACCESS_SETSTATE;
		GE_OK(lkb_setacl(lb, acl), 0);

		GE_OK(lkb_setstate(lb, 0xa5a5a5a5), 0);
		GE_OK(lkb_getstate(lb, &state), 0);
		EQ_OK(state, 0xa5a5a5a5);

		LE_OK(lkb_setfile(lb, -1), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_SETFD;
		EQ_OK(lkb_setacl(lb, acl), 0);

		GE_OK(lkb_setfile(lb, -1), 0);

		LE_OK(lkb_getfile(lb), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_GETFD;
		GE_OK(lkb_setacl(lb, acl), 0);

		LE_OK(lkb_getfile(lb), -1);
		EQ_OK(errno, ENOENT);

		GE_OK(lkb_setfile(lb, 0), 0);
		GE_OK(fdFile = lkb_getfile(lb), 0);
		if (fdFile >= 0)
			close(fdFile);
		GE_OK(lkb_setfile(lb, -1), 0);
		LE_OK(lkb_getfile(lb), -1);
		EQ_OK(errno, ENOENT);

		LE_OK(lkb_getacl(lb, 0, 0, &sizeneeded), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_GETACL;
		GE_OK(lkb_setacl(lb, acl), 0);

		LE_OK(lkb_getacl(lb, 0, 0, &sizeneeded), -1);
		EQ_OK(errno, ENOMEM);
		EQ_OK(sizeneeded, LKB_ACL_SIZE(acl->la_header.lah_n_entries));

		GE_OK(lkb_getacl(lb,
				 aclout,
				 LKB_ACL_SIZE(acl->la_header.lah_n_entries),
				 &sizeneeded), 0);
		EQ_OK(acl->la_header.lah_version, aclout->la_header.lah_version);
		EQ_OK(acl->la_header.lah_n_entries, aclout->la_header.lah_n_entries);
		EQ_OK(acl->la_entries[0].lae_idtype, aclout->la_entries[0].lae_idtype);
		EQ_OK(acl->la_entries[0].lae_id, aclout->la_entries[0].lae_id);
		EQ_OK(acl->la_entries[0].lae_access, aclout->la_entries[0].lae_access);
		EQ_OK(acl->la_entries[1].lae_idtype, aclout->la_entries[1].lae_idtype);
		EQ_OK(acl->la_entries[1].lae_id, aclout->la_entries[1].lae_id);
		EQ_OK(acl->la_entries[1].lae_access, aclout->la_entries[1].lae_access);

		GE_OK(lkb_create(0, "test-box-1", 0, 0, 0), -1);
		GE_OK(errno, EEXIST);

		GE_OK(lb2 = lkb_create(1, "test-box-1", 0, 0, 0), 0);

		if (lb2 >= 0)
		{
			LE_OK(lkb_create(1, "test-box-1", 0, 0, 0), -1);
			GE_OK(lkb_close(lb2), 0);

			GE_OK(lb2 = lkb_create(1, "test-box-1", 0, 0, 0), 0);
			if (lb2 >= 0)
				lkb_close(lb2);
		}

		LE_OK(lkb_open(0, "test-box-1"), -1);
		EQ_OK(errno, EPERM);

		acl->la_entries[0].lae_access |= LKB_ACCESS_OPEN;
		GE_OK(lkb_setacl(lb, acl), 0);

		GE_OK(lb2 = lkb_open(0, "test-box-1"), 0);

		if (lb2 >= 0)
		{
			LE_OK(lkb_lock(lb, LKB_LOCK_DATA), -1);
			EQ_OK(errno, EPERM);

			acl->la_entries[0].lae_access |= LKB_ACCESS_LOCK;
			GE_OK(lkb_setacl(lb, acl), 0);

			GE_OK(lkb_lock(lb, LKB_LOCK_DATA), 0);
			LE_OK(lkb_lock(lb2, LKB_LOCK_DATA | LKB_LOCK_NOBLOCK), -1);
			EQ_OK(errno, EWOULDBLOCK);

			alarm(3);
			LE_OK(lkb_lock(lb2, LKB_LOCK_DATA), -1);
			EQ_OK(errno, EINTR);

			GE_OK(lkb_lock(lb2, LKB_LOCK_STATE | LKB_LOCK_NOBLOCK), 0);

			GE_OK(lkb_unlock(lb), 0);
			GE_OK(lkb_lock(lb2, LKB_LOCK_DATA |
					    LKB_LOCK_FILE |
					    LKB_LOCK_ACL |
					    LKB_LOCK_NOBLOCK), 0);

			GE_OK(lkb_getacl(lb,
					 aclout,
					 LKB_ACL_SIZE(acl->la_header.lah_n_entries),
					 &sizeneeded), 0);

			aclout->la_entries[0].lae_access &= ~LKB_ACCESS_READ;

			LE_OK(lkb_setdata(lb, "AbC", 3, 0), -1);
			EQ_OK(errno, EBUSY);
			GE_OK(lkb_getdata(lb, buffer, 3, 0), 3);
			buffer[3] = 0;
			S_NE_OK(buffer, "AbC");

			LE_OK(lkb_setstate(lb, 0x12345678), -1);
			EQ_OK(errno, EBUSY);
			GE_OK(lkb_getstate(lb, &state), 0);
			NE_OK(state, 0x12345678);

			LE_OK(lkb_setfile(lb, 0), 0);
			EQ_OK(errno, EBUSY);
			LE_OK(lkb_getfile(lb), -1);
			EQ_OK(errno, ENOENT);

			LE_OK(lkb_setacl(lb, aclout), -1);
			EQ_OK(errno, EBUSY);
			GE_OK(lkb_getacl(lb, aclout2, LKB_ACL_SIZE(aclout->la_header.lah_n_entries), &sizeneeded), 0);
			NE_OK(aclout->la_entries[0].lae_access,
			      aclout2->la_entries[0].lae_access);

			GE_OK(lkb_setdata(lb2, "123", 3, 0), 0);
			GE_OK(lkb_setstate(lb2, 0x87654321), 0);
			GE_OK(lkb_setfile(lb2, 0), 0);
			GE_OK(lkb_setacl(lb2, aclout), 0);
			GE_OK(lkb_getstate(lb2, &state), 0);
			EQ_OK(state, 0x87654321);
			GE_OK(fdFile = lkb_getfile(lb2), 0);
			if (fdFile >= 0);
				close(fdFile);
			GE_OK(lkb_setfile(lb2, -1), 0);
			LE_OK(lkb_getfile(lb2), -1);
			EQ_OK(errno, ENOENT);
			GE_OK(lkb_getacl(lb2, aclout2, LKB_ACL_SIZE(aclout->la_header.lah_n_entries), &sizeneeded), 0);
			EQ_OK(aclout->la_entries[0].lae_access,
			      aclout2->la_entries[0].lae_access);

			LE_OK(lkb_getdata(lb2, buffer, 3, 0), -1);
			EQ_OK(errno, EPERM);
			GE_OK(lkb_setacl(lb2, acl), 0);

			GE_OK(lkb_getdata(lb, buffer, 3, 0), 3);
			S_OK(buffer, "123");

			GE_OK(lkb_getacl(lb, aclout2, LKB_ACL_SIZE(aclout->la_header.lah_n_entries), &sizeneeded), 0);
			EQ_OK(acl->la_entries[0].lae_access,
			      aclout2->la_entries[0].lae_access);

			GE_OK(lkb_unlock(lb2), 0);

			GE_OK(lkb_setdata(lb, "456", 3, 0), 0);
			GE_OK(lkb_setstate(lb, 0x01010101), 0);
			GE_OK(lkb_setfile(lb, 0), 0);
			GE_OK(lkb_setacl(lb, aclout), 0);
			GE_OK(lkb_getstate(lb, &state), 0);
			EQ_OK(state, 0x01010101);
			GE_OK(fdFile = lkb_getfile(lb), 0);
			if (fdFile >= 0);
				close(fdFile);
			GE_OK(lkb_setfile(lb, -1), 0);
			LE_OK(lkb_getfile(lb), -1);
			EQ_OK(errno, ENOENT);
			GE_OK(lkb_getacl(lb, aclout2, LKB_ACL_SIZE(aclout->la_header.lah_n_entries), &sizeneeded), 0);
			EQ_OK(aclout->la_entries[0].lae_access,
			      aclout2->la_entries[0].lae_access);

			LE_OK(lkb_getdata(lb, buffer, 3, 0), -1);
			EQ_OK(errno, EPERM);
			GE_OK(lkb_setacl(lb, acl), 0);

			GE_OK(lkb_getdata(lb, buffer, 3, 0), 3);
			S_OK(buffer, "456");

			EQ_OK(lkb_getusers(lb), 2);

			GE_OK(lkb_close(lb2), 0);

			EQ_OK(lkb_getusers(lb), 1);
		}
		
		lkb_close(lb);

		LE_OK(lkb_size(lb), -1);
		EQ_OK(errno, ENOENT);
	}

	NE_OK(lb = lkb_create(0, 0, 0, 0, 0), LOCKBOX_ERROR);
	if (lb != LOCKBOX_ERROR)
	{
		size_t	sizeneeded = -1;

		LE_OK(lkb_getname(lb, buffer, 0, &sizeneeded), -1);
		EQ_OK(errno, ENOMEM);
		EQ_OK(sizeneeded, 10);

		GE_OK(lkb_getname(lb, buffer, 10, &sizeneeded), 0);
		S_OK(buffer, "#00000000");
		GE_OK(lkb_close(lb), 0);
	}

	NE_OK(lb = lkb_create(0, 0, 0, 0, 0), LOCKBOX_ERROR);
	if (lb != LOCKBOX_ERROR)
	{
		size_t	sizeneeded = -1;

		LE_OK(lkb_getname(lb, buffer, 0, &sizeneeded), -1);
		EQ_OK(errno, ENOMEM);
		EQ_OK(sizeneeded, 10);

		GE_OK(lkb_getname(lb, buffer, 10, &sizeneeded), 0);
		S_OK(buffer, "#00000001");
		GE_OK(lkb_close(lb), 0);
	}

	NE_OK(lb = lkb_create(0, "test", 0, 0, 0), LOCKBOX_ERROR);
	if (lb != LOCKBOX_ERROR)
	{
		fd_set fds;
		fd_set fdsOrig;
		fd_set fdsZero;
		struct timeval tv;
		struct timeval tvOrig;

		switch(fork())
		{
		case 0:
			lkb_closevault();
			sleep(8);
			GE_OK(fdVault = lkb_openvault(vaultname), 0);
			GE_OK(lb = lkb_open(0, "test"), 0);
			if (lb >= 0)
			{
				lkb_lock(lb, LKB_LOCK_DATA);
				sleep(8);
				GE_OK(lkb_setstate(lb, 0x00000001), 0);
				sleep(8);
				GE_OK(lkb_setstate(lb, 0x00000020), 0);
				sleep(8);
				GE_OK(lkb_unlock(lb), 0);
				sleep(8);
				GE_OK(lkb_close(lb), 0);
				sleep(8);
				lkb_closevault();
			}
			exit(0);
			break;

		case -1:
			perror("fork");
			break;

		default:
			FD_ZERO(&fdsZero);
			fdsOrig = fdsZero;
			FD_SET(fdVault, &fdsOrig);
			tvOrig.tv_sec = 16;
			tvOrig.tv_usec = 0;

			GE_OK(lkb_resetallselects(), 0);
			GE_OK(lkb_setselectcriterion(lb, LKB_SELECT_USERS_GREATER_THAN, 1), 0);
			fds = fdsOrig;
			tv = tvOrig;
			EQ_OK(select(fdVault + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			NE_OK(FD_ISSET(fdVault, &fds), 0);
			EQ_OK(lkb_getselectableboxes(1, &lb2), 1);
			EQ_OK(lb2, lb);
			EQ_OK(lkb_getusers(lb), 2);

			GE_OK(lkb_resetallselects(), 0);
			GE_OK(lkb_setselectcriterion(lb, LKB_SELECT_FLAGS, 0x00000001), 0);
			fds = fdsOrig;
			tv = tvOrig;
			EQ_OK(select(fdVault + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			NE_OK(FD_ISSET(fdVault, &fds), 0);
			EQ_OK(lkb_getselectableboxes(1, &lb2), 1);
			EQ_OK(lb2, lb);
			GE_OK(lkb_getstate(lb, &state), 0);
			EQ_OK(state, 0x00000001);

			GE_OK(lkb_resetallselects(), 0);
			GE_OK(lkb_setselectcriterion(lb, LKB_SELECT_FLAGS, 0x00000020), 0);
			fds = fdsOrig;
			tv = tvOrig;
			EQ_OK(select(fdVault + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			NE_OK(FD_ISSET(fdVault, &fds), 0);
			EQ_OK(lkb_getselectableboxes(1, &lb2), 1);
			EQ_OK(lb2, lb);
			GE_OK(lkb_getstate(lb, &state), 0);
			EQ_OK(state, 0x00000020);

			GE_OK(lkb_resetallselects(), 0);
			GE_OK(lkb_setselectcriterion(lb, LKB_SELECT_LOCKAVAIL, LKB_LOCK_DATA), 0);
			fds = fdsOrig;
			tv = tvOrig;
			EQ_OK(select(fdVault + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			NE_OK(FD_ISSET(fdVault, &fds), 0);
			EQ_OK(lkb_getselectableboxes(1, &lb2), 1);
			EQ_OK(lb2, lb);
			GE_OK(lkb_lock(lb, LKB_LOCK_DATA | LKB_LOCK_NOBLOCK), 0);
			GE_OK(lkb_unlock(lb), 0);

			GE_OK(lkb_resetallselects(), 0);
			GE_OK(lkb_setselectcriterion(lb, LKB_SELECT_USERS_LESS_THAN, 2), 0);
			fds = fdsOrig;
			tv = tvOrig;
			EQ_OK(select(fdVault + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			NE_OK(FD_ISSET(fdVault, &fds), 0);
			EQ_OK(lkb_getselectableboxes(1, &lb2), 1);
			EQ_OK(lb2, lb);
			EQ_OK(lkb_getusers(lb), 1);

			GE_OK(lkb_close(lb), 0);

			break;
		}


	}

	NE_OK(lb = lkb_create(0, "test", 0, 0, 0), LOCKBOX_ERROR);
	if (lb != LOCKBOX_ERROR)
	{
		int	fdSelect;
		fd_set fds;
		fd_set fdsZero;
		struct timeval tv;
		struct timeval tvOrig;
		lockbox_select_criterion_setting lscs;
		lockbox_select_fd_entry lsfe;

		switch(fork())
		{
		case 0:
			lkb_closevault();
			sleep(8);
			GE_OK(fdVault = lkb_openvault(vaultname), 0);
			GE_OK(lb = lkb_open(0, "test"), 0);
			if (lb >= 0)
			{
				lkb_lock(lb, LKB_LOCK_DATA);
				sleep(8);
				GE_OK(lkb_setstate(lb, 0x00000001), 0);
				sleep(8);
				GE_OK(lkb_setstate(lb, 0x00000020), 0);
				sleep(8);
				GE_OK(lkb_unlock(lb), 0);
				sleep(8);
				GE_OK(lkb_close(lb), 0);
				sleep(8);
				lkb_closevault();
			}
			exit(0);
			break;

		case -1:
			perror("fork");
			break;

		default:
			lsfe.lsfe_id = lb;
			lsfe.lsfe_settings = &lscs;
			lsfe.lsfe_criteria = 1;

			FD_ZERO(&fdsZero);
			tvOrig.tv_sec = 16;
			tvOrig.tv_usec = 0;

			lscs.lscs_criterion = LKB_SELECT_USERS_GREATER_THAN;
			lscs.lscs_value = 2;
			fds = fdsZero;
			GE_OK(fdSelect = lkb_createselectfd(&lsfe, 1), 0);
			FD_SET(fdSelect, &fds);
			tv = tvOrig;
			EQ_OK(select(fdSelect + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			close(fdSelect);
			NE_OK(FD_ISSET(fdSelect, &fds), 0);
			EQ_OK(lkb_getusers(lb), 2);

			lscs.lscs_criterion = LKB_SELECT_FLAGS;
			lscs.lscs_value = 0x00000001;
			fds = fdsZero;
			GE_OK(fdSelect = lkb_createselectfd(&lsfe, 1), 0);
			FD_SET(fdSelect, &fds);
			tv = tvOrig;
			EQ_OK(select(fdSelect + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			close(fdSelect);
			NE_OK(FD_ISSET(fdSelect, &fds), 0);
			GE_OK(lkb_getstate(lb, &state), 0);
			EQ_OK(state, 0x00000001);

			lscs.lscs_criterion = LKB_SELECT_FLAGS;
			lscs.lscs_value = 0x00000020;
			fds = fdsZero;
			GE_OK(fdSelect = lkb_createselectfd(&lsfe, 1), 0);
			FD_SET(fdSelect, &fds);
			tv = tvOrig;
			EQ_OK(select(fdSelect + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			close(fdSelect);
			NE_OK(FD_ISSET(fdSelect, &fds), 0);
			GE_OK(lkb_getstate(lb, &state), 0);
			EQ_OK(state, 0x00000020);

			lscs.lscs_criterion = LKB_SELECT_LOCKAVAIL;
			lscs.lscs_value = LKB_LOCK_DATA;
			fds = fdsZero;
			GE_OK(fdSelect = lkb_createselectfd(&lsfe, 1), 0);
			FD_SET(fdSelect, &fds);
			tv = tvOrig;
			EQ_OK(select(fdSelect + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			close(fdSelect);
			NE_OK(FD_ISSET(fdSelect, &fds), 0);
			GE_OK(lkb_lock(lb, LKB_LOCK_DATA | LKB_LOCK_NOBLOCK), 0);
			GE_OK(lkb_unlock(lb), 0);

			lscs.lscs_criterion = LKB_SELECT_USERS_LESS_THAN;
			lscs.lscs_value = 3;
			fds = fdsZero;
			GE_OK(fdSelect = lkb_createselectfd(&lsfe, 1), 0);
			FD_SET(fdSelect, &fds);
			tv = tvOrig;
			EQ_OK(select(fdSelect + 1, &fdsZero, &fdsZero, &fds, &tv), 1);
			close(fdSelect);
			NE_OK(FD_ISSET(fdSelect, &fds), 0);
			EQ_OK(lkb_getusers(lb), 1);

			GE_OK(lkb_close(lb), 0);

			break;
		}


	}

	lkb_closevault();

	return status;
}
