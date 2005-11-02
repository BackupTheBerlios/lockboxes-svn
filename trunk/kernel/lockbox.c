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

#include <linux/config.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/file.h>

#include "../include/linux/lockbox.h"
#include "lockbox-internal.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Troy Rollo <linux@troy.rollo.name>");
MODULE_DESCRIPTION("Kernel implementation of the lockbox API");

static 	lockbox_vault *vault_list = 0;
struct semaphore vaultlist_lock;

static int is_lockbox_file(struct file *f);

static int
get_user_string(char const *str, char **kstring)
{
	int len = strlen_user(str);

	char *kernelstring;

	if (!len)
		return 0;
	kernelstring = kmalloc(len, GFP_KERNEL);
	if (!kernelstring)
		return -ENOMEM;
	if (copy_from_user(kernelstring, str, len) < 0 ||
	    kernelstring[len - 1])
	{
		kfree(kernelstring);
		return -EFAULT;
	}
	*kstring = kernelstring;
	return 0;
}

static void *
opt_alloc(	size_t size)
{
	if (size > PAGE_SIZE)
		return vmalloc(size);
	else
		return kmalloc(size, GFP_KERNEL);
}

static void
opt_free(	void *pv,
		size_t size)
{
	if (size > PAGE_SIZE)
		vfree(pv);
	else
		kfree(pv);
}

void
free_acl(lockbox_acl *a)
{
	return opt_free(a, LKB_ACL_SIZE(a->la_header.lah_n_entries));
}

static int
copy_user_data(	void const *puser,
		size_t	size,
		void	**pkernel)
{
	void *pkdata;

	if (!access_ok(VERIFY_READ, puser, size))
		return -EFAULT;
	pkdata = opt_alloc(size);
	if (!pkdata)
		return -ENOMEM;
	if (copy_from_user(pkdata, puser, size))
	{
		opt_free(pkdata, size);
		return -EFAULT;
	}
	*pkernel = pkdata;
	return 0;
}

static int
get_user_acl(	lockbox_acl const *pacl,
		lockbox_acl **ppkacl)
{
	lockbox_acl_header aclh;
	lockbox_acl *pkacl;

	if (pacl)
	{
		 if (copy_from_user(&aclh,
				    pacl,
				    sizeof(aclh)))
			 return -EFAULT;
		 return copy_user_data(pacl, LKB_ACL_SIZE(aclh.lah_n_entries), (void **) ppkacl);
	}
	else
	{
		pkacl = opt_alloc(LKB_ACL_SIZE(2));

		if (!pkacl)
			return -ENOMEM;

		pkacl->la_header.lah_version = LKB_ACL_VERSION;
		pkacl->la_header.lah_n_entries = 2;
		pkacl->la_entries[0].lae_idtype = LKB_IDTYPE_USER;
		pkacl->la_entries[0].lae_id = current->euid;
		pkacl->la_entries[0].lae_access = LKB_ACCESS_ALL;
		pkacl->la_entries[1].lae_idtype = LKB_IDTYPE_WORLD;
		pkacl->la_entries[1].lae_id = 0;
		pkacl->la_entries[1].lae_access = LKB_ACCESS_READ |
						  LKB_ACCESS_OPEN;
		*ppkacl = pkacl;
		return 0;
	}
}

static int
new_box(	char	*name,
		char const *data,
		size_t	size,
		lockbox_acl const *pacl,
		uint32_t shelf,
		lockbox_box **ppbox)
{
	char	*box_mem = 0;
	lockbox_acl *pkacl = 0;
	lockbox_box *newbox;
	int status = -ENOMEM;

	if ((newbox = kmalloc(sizeof(lockbox_box), GFP_KERNEL)) != 0 &&
	    (!size || (status = copy_user_data(data, size, (void **) &box_mem)) == 0) &&
	    (status = get_user_acl(pacl, &pkacl)) == 0)
	{
		memset(newbox, 0, sizeof(lockbox_box));
		newbox->lkb_b_name = name;
		newbox->lkb_b_data = box_mem;
		newbox->lkb_b_acl = pkacl;
		newbox->lkb_b_size = size;
		newbox->lkb_b_users = 1;
		newbox->lkb_b_shelf = shelf;
		init_MUTEX(&newbox->lkb_b_lock);
		init_waitqueue_head(&newbox->lkb_b_waitq);
		*ppbox = newbox;
	}
	else
	{
		if (box_mem)
			opt_free(box_mem, size);
		if (newbox)
			kfree(newbox);
		if (pkacl)
			opt_free(pkacl, LKB_ACL_SIZE(pkacl->la_header.lah_n_entries));
	}
	return status;
}

static void
free_box(lockbox_box *b)
{
	kfree(b->lkb_b_name);
	if (b->lkb_b_file)
		fput(b->lkb_b_file);
	opt_free(b->lkb_b_acl, LKB_ACL_SIZE(b->lkb_b_acl->la_header.lah_n_entries));
	if (b->lkb_b_data)
		opt_free(b->lkb_b_data, b->lkb_b_size);
	kfree(b);
}

static void
init_shelf(lockbox_shelf *s)
{
	init_MUTEX(&s->lkb_s_lock);
}

static lockbox_shelflist *
new_shelflist(void)
{
	lockbox_shelflist *sl = kmalloc(sizeof(lockbox_shelflist), GFP_KERNEL);

	if (sl)
	{
		int	i;

		sl->lkb_sl_next = 0;
		for (i = 0; i < IN_SHELFLIST_SHELVES; ++i)
			init_shelf(sl->lkb_sl_shelves + i);
	}
	return sl;
}

static lockbox_vault *
new_vault(char *vault_name)
{
	lockbox_vault *newvault = kmalloc(sizeof(lockbox_vault), GFP_KERNEL);

	if (newvault)
	{
		int	i;

		memset(newvault, 0, sizeof(lockbox_vault));
		init_MUTEX(&newvault->lkb_v_lock);
		newvault->lkb_v_name = vault_name;
		newvault->lkb_v_users = 1;
		for (i = 0; i < IN_VAULT_SHELVES; ++i)
			init_shelf(newvault->lkb_v_shelves + i);
	}
	return newvault;
}

static int
set_vault(	lockbox_perfile *perfile,
		char const *userstring)
{
	int	status = 0;
	char	*localstring;

	if (perfile->lkb_pf_vault)
		return -EFAULT; /* Setting a vault is irreversible */

	if (down_interruptible(&vaultlist_lock) < 0)
		return -EINTR;

	status = get_user_string(userstring, &localstring);
	if (status >= 0)
	{
		lockbox_vault **ploc = &vault_list;

		while (1)
		{
			if (!*ploc)
			{
				lockbox_vault *newvault = new_vault(localstring);

				if (!newvault)
				{
					status = -ENOMEM;
				}
				else
				{
					*ploc = newvault;
					perfile->lkb_pf_vault = newvault;
					localstring = 0;
				}
				break;
			}
			else if (!strcmp((*ploc)->lkb_v_name, localstring))
			{
				lockbox_vault *newvault = *ploc;

				++newvault->lkb_v_users;
				perfile->lkb_pf_vault = newvault;
				break;
			}
			ploc = &(*ploc)->lkb_v_next;
		}

		if (localstring)
			kfree(localstring);
	}

	up(&vaultlist_lock);

	return status;
}

static int
list_vaults(	char	*data,
		int	buffersize,
		int	*psizeneeded)
{
	int	status = 0;
	int	sizeneeded = 1;
	lockbox_vault *pvault;

	if (down_interruptible(&vaultlist_lock) < 0)
		return -EINTR;
	for (pvault = vault_list; pvault; pvault = pvault->lkb_v_next)
		sizeneeded += strlen(pvault->lkb_v_name) + 1;
	*psizeneeded = sizeneeded;
	if (sizeneeded <= buffersize)
	{
		char c;

		for (pvault = vault_list; pvault; pvault = pvault->lkb_v_next)
		{
			int	len = strlen(pvault->lkb_v_name) + 1;

			if (copy_to_user(data, pvault->lkb_v_name, len))
			{
				status = -EFAULT;
				break;
			}
			data += len;
		}
		c = 0;
		if (copy_to_user(data, &c, 1))
			status = -EFAULT;
	}
	else
	{
		status = -ENOMEM;
	}
	up(&vaultlist_lock);
	return status;
}

static void
free_vault(lockbox_vault *v)
{
	kfree(v->lkb_v_name);
	kfree(v);
}

static void
release_vault(lockbox_vault *v)
{
	if (!v)
		return;

	down(&vaultlist_lock);

	if (!--v->lkb_v_users)
	{
		lockbox_vault **ploc;

		for (ploc = &vault_list; *ploc != v; ploc = &(*ploc)->lkb_v_next);
		*ploc = v->lkb_v_next;
		free_vault(v);
	}

	up(&vaultlist_lock);
}

int
find_shelf(	lockbox_vault *v,
		uint32_t	shelf,
		int		is_interruptible,
		lockbox_shelf	**ps,
		int		creating)
{
	lockbox_shelflist **ppsl;
	lockbox_shelf *s;
	int	status;

	if (shelf < IN_VAULT_SHELVES)
	{
		*ps = v->lkb_v_shelves + shelf;
		return 0;
	}
	shelf -= IN_VAULT_SHELVES;
	if (is_interruptible)
	{
		if (down_interruptible(&v->lkb_v_lock) < 0)
			return -EINTR;
	}
	else
	{
		down(&v->lkb_v_lock);
	}
	s = 0;
	status = 0;
	for (ppsl = &v->lkb_v_shelflist; *ppsl; ppsl = &(*ppsl)->lkb_sl_next)
	{
		if (shelf < IN_SHELFLIST_SHELVES)
		{
			s = (*ppsl)->lkb_sl_shelves + shelf;
			break;
		}
		shelf -= IN_SHELFLIST_SHELVES;
	}
	if (s)
	{
		/* Do nothing */
	}
	else if (creating)
	{
		while (1)
		{
			*ppsl = new_shelflist();
			if (!*ppsl)
			{
				status = -ENOMEM;
				break;
			}
			if (shelf < IN_SHELFLIST_SHELVES)
			{
				s = (*ppsl)->lkb_sl_shelves + shelf;
				break;
			}
			ppsl = &(*ppsl)->lkb_sl_next;
		}
	}
	else
	{
		status = -ENOENT;
	}
	up(&v->lkb_v_lock);
	*ps = s;
	return status;
}

static void
wake_box_sleepers(	lockbox_box *b,
			int destroying_queue)
{
	if (destroying_queue)
		wake_up_all(&b->lkb_b_waitq);
	else
		wake_up(&b->lkb_b_waitq);
}

static void
clean_box_holder(lockbox_vault *v,
		lockbox_box *b)
{
	int need_free;

	down(&b->lkb_b_lock);
	need_free = (!--b->lkb_b_holders &&
		     !b->lkb_b_users);
	up(&b->lkb_b_lock);
	if (need_free)
	{
		lockbox_shelf *s;

		find_shelf(v, b->lkb_b_shelf, 0, &s, 0);
		down(&s->lkb_s_lock);
		down(&b->lkb_b_lock);
		if (!b->lkb_b_users && !b->lkb_b_holders)
		{
			lockbox_box **ploc;

			for (ploc = &s->lkb_s_boxlist;
			     *ploc;
			     ploc = &(*ploc)->lkb_b_next)
			{
				if (b == *ploc)
				{
					*ploc = b->lkb_b_next;
					break;
				}
			}
		}
		else
		{
			need_free = 0;
		}
		up(&b->lkb_b_lock);
		up(&s->lkb_s_lock);
		if (need_free)
			free_box(b);
	}
}

static void
release_box(	lockbox_vault *v,
		lockbox_box *b,
		uint32_t locks)
{
	int	clean;

	down(&b->lkb_b_lock);
	clean = !--b->lkb_b_users;
	++b->lkb_b_holders;
	b->lkb_b_userlocks &= ~ locks;
	up(&b->lkb_b_lock);

	wake_box_sleepers(b, clean);
	clean_box_holder(v, b);
}

static void
free_perfile(lockbox_perfile *pf)
{
	int	i;
	lockbox_boxlist *l, *n;

	if (pf->lkb_pf_vault)
	{
		release_vault(pf->lkb_pf_vault);
		for (i = 0; i < IN_PERFILE_BOXES; ++i)
		{
			if (pf->lkb_pf_boxes[i].lkb_bu_box)
				release_box(pf->lkb_pf_vault,
					    pf->lkb_pf_boxes[i].lkb_bu_box,
					    pf->lkb_pf_boxes[i].lkb_bu_locks_held);
		}
		for (l = pf->lkb_pf_boxlist; l; l = n)
		{
			n = l->lkb_bl_next;
	
			for (i = 0; i < IN_BOXLIST_BOXES; ++i)
			{
				if (l->lkb_bl_boxes[i].lkb_bu_box)
					release_box(pf->lkb_pf_vault,
						    l->lkb_bl_boxes[i].lkb_bu_box,
						    l->lkb_bl_boxes[i].lkb_bu_locks_held);
			}
		}
	}
	kfree(pf);
}

static void
reset_boxuse_selects(lockbox_boxuse *bu)
{
	bu->lkb_bu_select_users_lt = LKB_SELECT_DISABLE_USERS_LT;
	bu->lkb_bu_select_users_gt = LKB_SELECT_DISABLE_USERS_GT;
	bu->lkb_bu_select_flags = 0;
	bu->lkb_bu_select_wantlock = 0;
}

static void
set_boxuse(	lockbox_boxuse *bu,
		lockbox_box *b)
{
	bu->lkb_bu_box = b;
	reset_boxuse_selects(bu);
}

static int
add_box_to_perfile(	lockbox_perfile *pf,
			lockbox_box *b,
			int	prelocked)
{
	int status = 0;
	int found = 0;

	if (prelocked)
		status = 0;
	else
		status = down_interruptible(&pf->lkb_pf_lock);
	if (status >= 0)
	{
		int	i;

		for (i = 0; i < IN_PERFILE_BOXES; ++i)
		{
			if (!pf->lkb_pf_boxes[i].lkb_bu_box)
			{
				set_boxuse(pf->lkb_pf_boxes + i, b);
				status = i;
				found = 1;
				break;
			}
		}
		if (!found)
		{
			lockbox_boxlist **bl = &pf->lkb_pf_boxlist;
			int	offset = IN_PERFILE_BOXES;

			while (*bl)
			{
				for (i = 0; i < IN_BOXLIST_BOXES; ++i)
				{
					if (!(*bl)->lkb_bl_boxes[i].lkb_bu_box)
					{
						set_boxuse((*bl)->lkb_bl_boxes + i, b);
						status = offset + i;
						found = 1;
						break;
					}
				}
				if (found)
					break;
				bl = &(*bl)->lkb_bl_next;
				offset += IN_BOXLIST_BOXES;
			}

			if (!found)
			{
				*bl = kmalloc(sizeof(lockbox_boxlist), GFP_KERNEL);
				if (*bl)
				{
					memset(*bl, 0, sizeof(lockbox_boxlist));
					status = offset;
					set_boxuse((*bl)->lkb_bl_boxes, b);
				}
				else
				{
					status = -ENOMEM;
				}
			}
		}
		if (!prelocked)
			up(&pf->lkb_pf_lock);
	}

	if (status < 0)
		release_box(pf->lkb_pf_vault, b, 0);
	return status;
}

static int
lockbox_access_ok(	lockbox_acl const *acl,
			int		flag)
{
	int	i;

	for (i = 0; i < acl->la_header.lah_n_entries; ++i)
	{
		if ((acl->la_entries[i].lae_access & flag) != flag)
			continue;
		switch (acl->la_entries[i].lae_idtype)
		{
		case LKB_IDTYPE_USER:
			if (acl->la_entries[i].lae_id != current->euid)
				continue;
			break;

		case LKB_IDTYPE_GROUP:
			if (!in_egroup_p(acl->la_entries[i].lae_id))
				continue;
			break;

		case LKB_IDTYPE_WORLD:
			break;

		case LKB_IDTYPE_PROCESS:
			if (acl->la_entries[i].lae_id != current->tgid)
				continue;
			break;

		default:
			continue;
		}
		return 1;
	}
	return 0;
}

static int
lockbox_create_new(	lockbox_perfile *pf,
			uint32_t	shelfid,
			char const	*name,
			void const	*data,
			size_t		size,
			lockbox_acl const *acl)
{
	lockbox_box **b;
	lockbox_vault *v = pf->lkb_pf_vault;
	lockbox_shelf *s;
	char	*kname;
	int	status;

	if (!v)
		return -EINVAL;
	status = find_shelf(v, shelfid, 1, &s, 1);
	if (status < 0)
		return status;
	if (name)
	{
		status = get_user_string(name, &kname);
		if (status >= 0 && !*kname)
		{
			/* Empty strings not allowed */
			kfree(kname);
			return -EINVAL;
		}
	}
	if (!name)
	{
		kname = kmalloc(10, GFP_KERNEL);
		if (!kname)
			return -ENOMEM;
		*kname = 0;
	}
	if (status >= 0)
	{
		status = down_interruptible(&s->lkb_s_lock);

		if (status >= 0)
		{
			b = &s->lkb_s_boxlist;
			if (!*kname)
				sprintf(kname, "#%08x", s->lkb_s_seqno++);
			
			while (1)
			{
				if (!*b)
				{
					/* We have reached the end of the list, so
					 * this name is OK to create
					 */
					status = new_box(kname, data, size, acl, shelfid, b);
					/* new_box takes ownership of kname, succeed or fail */
					kname = 0;
					break;
				}
				else if (strcmp((*b)->lkb_b_name, kname))
				{
					/* This name doesn't match, move on to the
					 * next one.
					 */
					b = &(*b)->lkb_b_next;
				}
				else if (unlikely(!name))
				{
					/* We're generating a name, but we've wrapped
					 * around and encountered this generated name.
					 * Move to the next sequence number and try
					 * again.
					 */
					sprintf(kname, "#%08x", s->lkb_s_seqno++);
					b = &s->lkb_s_boxlist;
				}
				else
				{
					/* The user-supplied name already exists */
					status = -EEXIST;
					break;
				}
			}
			up(&s->lkb_s_lock);
			/* Now we have created the lockbox on the shelf, we need to
			 * put it in the perfile's list
			 */
			if (status >= 0)
				status = add_box_to_perfile(pf, *b, 0);
		}
		if (kname)
			kfree(kname);
	}
	return status;
}

static int
lockbox_open_existing(	lockbox_perfile *pf,
			uint32_t	shelfid,
			char const	*name)
{
	int	status;
	lockbox_shelf *s;
	lockbox_vault *v = pf->lkb_pf_vault;
	char	*kname;

	if (!v)
		return -EINVAL;
	if (!name)
		return -EINVAL;
	status = find_shelf(v, shelfid, 1, &s, 0);
	if (status < 0)
		return status;
	status = get_user_string(name, &kname);
	if (status >= 0)
	{
		status = down_interruptible(&s->lkb_s_lock);

		if (status >= 0)
		{
			lockbox_box *b;

			status = -ENOENT;

			for (b = s->lkb_s_boxlist; b; b = b->lkb_b_next)
			{
				if (!strcmp(b->lkb_b_name, kname))
				{
					status = down_interruptible(&b->lkb_b_lock);
					if (status >= 0)
					{
						if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_OPEN))
						{
							status = -EPERM;
						}
						else
						{
							++b->lkb_b_users;
							status = add_box_to_perfile(pf, b, 0);
							if (status >= 0)
								++b->lkb_b_holders;
							else
								--b->lkb_b_users;
						}
						up(&b->lkb_b_lock);
					}
					break;
				}
			}

			up(&s->lkb_s_lock);

			if (status >= 0)
			{
				wake_box_sleepers(b, 0);
				clean_box_holder(v, b);
			}
		}
		kfree(kname);
	}
	return status;
}

static int
lockbox_find_box(lockbox_perfile *pf,
		lockbox_t id,
		lockbox_boxuse **bu)
{
	int	status = -ENOENT;

	if (id < IN_PERFILE_BOXES)
	{
		if (pf->lkb_pf_boxes[id].lkb_bu_box)
		{
			*bu = pf->lkb_pf_boxes + id;
			status = 0;
		}
	}
	else
	{
		lockbox_boxlist *bl;
		status = -ENOENT;

		id -= IN_PERFILE_BOXES;

		for (bl = pf->lkb_pf_boxlist; bl; bl = bl->lkb_bl_next)
		{
			if (id < IN_BOXLIST_BOXES)
			{
				if (bl->lkb_bl_boxes[id].lkb_bu_box)
				{
					*bu = bl->lkb_bl_boxes + id;
					status = 0;
				}
				break;
			}
			id -= IN_BOXLIST_BOXES;
		}
	}
	return status;
}

static int
lockbox_close_box(	lockbox_perfile *pf,
			lockbox_t	id)
{
	lockbox_boxuse *bu;
	int status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		bu->lkb_bu_box = 0;
		release_box(pf->lkb_pf_vault, b, bu->lkb_bu_locks_held);
		status = 0;
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_size(	lockbox_perfile *pf,
		lockbox_t	id)
{
	lockbox_boxuse *bu;
	int status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_READ))
				status = -EPERM;
			else
				status = b->lkb_b_size;
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_get_data(lockbox_perfile *pf,
		lockbox_t	id,
		char		*buffer,
		size_t		size,
		off_t		offset)
{
	lockbox_boxuse *bu;
	int status;

	if (offset < 0)
		return -EINVAL;
	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_READ))
			{
				status = -EPERM;
			}
			else if (offset >= b->lkb_b_size)
			{
				status = 0;
			}
			else
			{
				if (offset + size > b->lkb_b_size)
					size = b->lkb_b_size - offset;
				if (copy_to_user(buffer, b->lkb_b_data + offset, size))
					status = -EFAULT;
				else
					status = size;
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_set_data(lockbox_perfile *pf,
		lockbox_t	id,
		char const	*buffer,
		size_t		size,
		off_t		offset)
{
	lockbox_boxuse *bu;
	int status;

	if (offset < 0)
		return -EINVAL;
	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			size_t new_size = offset + size;

			if (b->lkb_b_userlocks & LKB_LOCK_DATA & ~bu->lkb_bu_locks_held)
			{
				status = -EBUSY;
			}
			else if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_WRITE))
			{
				status = -EPERM;
			}
			else if (new_size > b->lkb_b_size)
			{
				char *new_data = opt_alloc(new_size);

				if (!new_data)
				{
					status = -ENOMEM;
				}
				else
				{
					if (copy_from_user(new_data + offset,
								buffer,
								size))
					{
						opt_free(new_data, new_size);
						status = -EFAULT;
					}
					else
					{
						int copy_size = b->lkb_b_size;

						if (copy_size > offset)
							copy_size = offset;
						memcpy(new_data,
						       b->lkb_b_data,
						       copy_size);
						if (offset > copy_size)
							memset(new_data + copy_size,
							       0,
							       offset - copy_size);
						opt_free(b->lkb_b_data,
							b->lkb_b_size);
						b->lkb_b_data = new_data;
						b->lkb_b_size = new_size;
						status = size;
					}
				}
			}
			else if (copy_from_user(b->lkb_b_data + offset, buffer, size))
			{
				status = -EFAULT;
			}
			else
			{
				status = 0;
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_set_state(lockbox_perfile *pf,
		lockbox_t	id,
		uint32_t	state)
{
	lockbox_boxuse *bu;
	int status;
	int need_wakeups = 0;
	lockbox_box *b = 0;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		b = bu->lkb_bu_box;
		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_SETSTATE))
			{
				status = -EPERM;
			}
			else if (b->lkb_b_userlocks & LKB_LOCK_STATE & ~bu->lkb_bu_locks_held)
			{
				status = -EBUSY;
			}
			else
			{
				if (state & ~b->lkb_b_state)
				{
					need_wakeups = 1;
					++b->lkb_b_holders;
				}
				b->lkb_b_state = state;
				status = 0;
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	if (need_wakeups)
	{
		wake_box_sleepers(b, 0);
		clean_box_holder(pf->lkb_pf_vault, b);
	}
	return status;
}

static int
lockbox_get_state(lockbox_perfile *pf,
		lockbox_t	id,
		uint32_t	*state)
{
	lockbox_boxuse *bu;
	int status;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_GETSTATE))
			{
				status = -EPERM;
			}
			else
			{
				*state = b->lkb_b_state;
				status = 0;
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_set_file(lockbox_perfile *pf,
		lockbox_t	id,
		int		fd)
{
	lockbox_boxuse *bu;
	int status;
	struct file *f;
	
	if (fd < 0)
	{
		if (fd < -1)
			return -EINVAL;
		f = 0;
	}
	else
	{
		f = fget(fd);
		if (!f)
			return -ENOENT;
	}

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status >= 0)
	{
		status = lockbox_find_box(pf, id, &bu);
		if (status >= 0)
		{
			lockbox_box *b = bu->lkb_bu_box;

			status = down_interruptible(&b->lkb_b_lock);

			if (status >= 0)
			{
				if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_SETFD))
				{
					status = -EPERM;
				}
				else if (b->lkb_b_userlocks & LKB_LOCK_FILE & ~bu->lkb_bu_locks_held)
				{
					status = -EBUSY;
				}
				else
				{
					if (b->lkb_b_file)
						fput(b->lkb_b_file);
					if (f)
						get_file(f);
					b->lkb_b_file = f;
				}
				up(&b->lkb_b_lock);
			}
		}
		up(&pf->lkb_pf_lock);
	}
	if (f)
		fput(f);
	return status;
}

static int
lockbox_get_file(lockbox_perfile *pf,
		lockbox_t	id)
{
	lockbox_boxuse *bu;
	int status;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_GETFD))
			{
				status = -EPERM;
			}
			else if (!b->lkb_b_file)
			{
				status = -ENOENT;
			}
			else if ((status = get_unused_fd()) >= 0)
			{
				get_file(b->lkb_b_file);
				fd_install(status, b->lkb_b_file);
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_get_users(lockbox_perfile *pf,
		lockbox_t	id)
{
	lockbox_boxuse *bu;
	int status;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			status = b->lkb_b_users;
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_get_name(	lockbox_perfile *pf,
			lockbox_t	id,
			char		*name,
			size_t		bufsize,
			size_t		*sizeneeded)
{
	lockbox_boxuse *bu;
	int status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;
		int len = strlen(b->lkb_b_name) + 1;

		*sizeneeded = len;
		if (len > bufsize)
			status = -ENOMEM;
		else if (copy_to_user(name, b->lkb_b_name, len))
			status = -EFAULT;
		else
			status = 0;
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_set_acl(lockbox_perfile *pf,
		lockbox_t	id,
		lockbox_acl const *acl)
{
	lockbox_boxuse *bu;
	int status;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_SETACL))
			{
				status = -EPERM;
			}
			else if (b->lkb_b_userlocks & LKB_LOCK_ACL & ~bu->lkb_bu_locks_held)
			{
				status = -EBUSY;
			}
			else
			{
				lockbox_acl *new_acl;

				status = get_user_acl(acl, &new_acl);

				if (status >= 0)
				{
					free_acl(b->lkb_b_acl);
					b->lkb_b_acl = new_acl;
					status = 0;
				}
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_get_acl(lockbox_perfile *pf,
		lockbox_t	id,
		lockbox_acl	*acl,
		size_t		size,
		size_t		*sizeneeded)
{
	lockbox_boxuse *bu;
	int status;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
	{
		lockbox_box *b = bu->lkb_bu_box;

		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_GETACL))
			{
				status = -EPERM;
			}
			else
			{
				*sizeneeded = LKB_ACL_SIZE(b->lkb_b_acl->la_header.lah_n_entries);

				if (size < *sizeneeded)
					status = -ENOMEM;
				else if (copy_to_user(acl,
						b->lkb_b_acl,
						*sizeneeded))
					status = -EFAULT;
				else
					status = 0;
			}
			up(&b->lkb_b_lock);
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_list_boxes(	lockbox_perfile *pf,
			int	shelf,
			char	*data,
			int	buffersize,
			int	*psizeneeded)
{
	int	status = 0;
	lockbox_vault *v;
	lockbox_shelf *s;

	v = pf->lkb_pf_vault;
	if (!v)
		return -EINVAL;
	status = find_shelf(v, shelf, 1, &s, 0);
	if (status < 0)
		return status;
	if (s)
		status = down_interruptible(&s->lkb_s_lock);
	if (status >= 0)
	{
		lockbox_box *b;
		int	sizeneeded = 1;

		if (s)
		{
			for (b = s->lkb_s_boxlist; b; b = b->lkb_b_next)
				sizeneeded += strlen(b->lkb_b_name) + 1;
		}
		*psizeneeded = sizeneeded;
		if (sizeneeded <= buffersize)
		{
			char c;

			if (s)
			{
				for (b = s->lkb_s_boxlist; b; b = b->lkb_b_next)
				{
					int len = strlen(b->lkb_b_name) + 1;

					if (copy_to_user(data, b->lkb_b_name, len))
					{
						status = -EFAULT;
						break;
					}
					data += len;
				}
			}
			c = 0;
			if (copy_to_user(data, &c, 1))
				status = -EFAULT;

		}
		else
		{
			status = -ENOMEM;
		}
		if (s)
			up(&s->lkb_s_lock);
	}
	return status;
}

static int
lockbox_acquire_lock(	lockbox_perfile *pf,
			lockbox_boxuse *bu,
			lockbox_box	*b,
			uint32_t	flags,
			int		*status)
{
	int	retval = 1;

	if (bu->lkb_bu_box != b)
	{
		/* Somebody has closed the box on us! */
		*status = -ENOENT;
		return 1;
	}

	if (down_interruptible(&pf->lkb_pf_lock) < 0)
	{
		*status = -EINTR;
		return 1;
	}
	

	if (down_interruptible(&b->lkb_b_lock) < 0)
	{
		*status = -EINTR;
		retval = 1;
	}
	else
	{
		if (flags & (b->lkb_b_userlocks & ~bu->lkb_bu_locks_held))
		{
			*status = -EWOULDBLOCK;
			retval = 0;
		}
		else
		{
			b->lkb_b_userlocks |= flags;
			bu->lkb_bu_locks_held |= flags;
			*status = 0;
			retval = 1;
		}
		up(&b->lkb_b_lock);
	}
	up(&pf->lkb_pf_lock);
	return retval;
}

static int
lockbox_lock(	lockbox_perfile *pf,
		lockbox_t id,
		uint32_t flags_in)
{
	lockbox_boxuse *bu;
	int	status;
	uint32_t flags = flags_in & LKB_LOCK_ALL;
	int	no_block = (flags_in & LKB_LOCK_NOBLOCK) ? 1 : 0;
	int	waiting;
	lockbox_box *b = 0;

	status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	waiting = 0;

	status = lockbox_find_box(pf, id, &bu);

	if (status >= 0)
	{
		b = bu->lkb_bu_box;
		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			if (!lockbox_access_ok(b->lkb_b_acl, LKB_ACCESS_LOCK))
			{
				status = -EPERM;
			}
			else
			{
				++b->lkb_b_holders;
				status = 0;
			}
			up(&b->lkb_b_lock);
		}
	}

	up(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = 0;

	if (no_block)
	{
		lockbox_acquire_lock(pf, bu, b, flags, &status);
	}
	else
	{
		status = -EWOULDBLOCK;

		wait_event_interruptible(b->lkb_b_waitq,
			   lockbox_acquire_lock(pf, bu, b, flags, &status));
		if (status == -EWOULDBLOCK)
			status = -EINTR;
	}

	clean_box_holder(pf->lkb_pf_vault, b);
	return status;
}

static int
lockbox_unlock(	lockbox_perfile *pf,
		lockbox_t id)
{
	lockbox_boxuse *bu;
	int need_wakeup = 0;
	lockbox_box *b = 0;
	int status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0 && bu->lkb_bu_locks_held)
	{
		b = bu->lkb_bu_box;
		status = down_interruptible(&b->lkb_b_lock);

		if (status >= 0)
		{
			need_wakeup = 1;
			++b->lkb_b_holders;
			b->lkb_b_userlocks &= ~bu->lkb_bu_locks_held;
			bu->lkb_bu_locks_held = 0;
			up(&b->lkb_b_lock);
		}
	}
	if (need_wakeup)
	{
		wake_box_sleepers(b, 0);
		clean_box_holder(pf->lkb_pf_vault, b);
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
set_criterion(	lockbox_boxuse *bu,
		uint32_t	type,
		uint32_t	value)
{
	int status = 0;

	switch (type)
	{
	case LKB_SELECT_USERS_LESS_THAN:
		bu->lkb_bu_select_users_lt = value;
		break;

	case LKB_SELECT_USERS_GREATER_THAN:
		bu->lkb_bu_select_users_gt = value;
		break;

	case LKB_SELECT_FLAGS:
		bu->lkb_bu_select_flags = value;
		break;

	case LKB_SELECT_LOCKAVAIL:
		bu->lkb_bu_select_wantlock = value;
		break;

	default:
		status = -EINVAL;
	}
	return status;
}

static int
lockbox_setselectcriterion(	lockbox_perfile	*pf,
				lockbox_t	id,
				uint32_t	type,
				uint32_t	value)
{
	lockbox_boxuse *bu;
	int status = down_interruptible(&pf->lkb_pf_lock);

	if (status < 0)
		return status;

	status = lockbox_find_box(pf, id, &bu);
	if (status >= 0)
		status = set_criterion(bu, type, value);
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_getselectstate(	lockbox_boxuse *bu,
			lockbox_box *b)
{
	int	has_selitem = 0;

	if (bu->lkb_bu_select_users_lt != LKB_SELECT_DISABLE_USERS_LT)
	{
		has_selitem = 1;
		if (bu->lkb_bu_select_users_lt > b->lkb_b_users)
			return 2;
	}
	if (bu->lkb_bu_select_users_gt != LKB_SELECT_DISABLE_USERS_GT)
	{
		has_selitem = 1;
		if (bu->lkb_bu_select_users_gt < b->lkb_b_users)
			return 2;
	}
	if (bu->lkb_bu_select_flags)
	{
		has_selitem = 1;
		if (bu->lkb_bu_select_flags & b->lkb_b_state)
			return 2;
	}
	if (bu->lkb_bu_select_wantlock)
	{
		has_selitem = 1;
		if (!(bu->lkb_bu_select_wantlock & b->lkb_b_userlocks))
			return 2;
	}
	return has_selitem;
}

static int
lockbox_getselectableboxes(	lockbox_perfile *pf,
				lockbox_t	*array,
				size_t		arraysize)
{
	lockbox_boxlist *bl;
	lockbox_boxuse *bu;
	lockbox_box *b;
	int status;
	int i;
	int offset;

	if (down_interruptible(&pf->lkb_pf_lock))
		return -EINTR;

	status = 0;

	for (i = 0, bu = pf->lkb_pf_boxes;
	     arraysize && i < IN_PERFILE_BOXES;
	     ++i, ++bu)
	{
		b = bu->lkb_bu_box;

		if (b)
		{
			if (down_interruptible(&b->lkb_b_lock) < 0)
			{
				arraysize = 0;
				status = -EINTR;
			}
			else
			{
				if (lockbox_getselectstate(bu, b) == 2)
				{
					if (put_user(i, array) < 0)
					{
						arraysize = 0;
						status = -EFAULT;
					}
					else
					{
						++status;
						--arraysize;
					}
				}
				up(&b->lkb_b_lock);
			}
		}
	}

	for (bl = pf->lkb_pf_boxlist, offset = IN_PERFILE_BOXES;
	     arraysize && bl;
	     bl = bl->lkb_bl_next, offset += IN_BOXLIST_BOXES)
	{
		for (i = 0, bu = bl->lkb_bl_boxes;
		     arraysize && i < IN_BOXLIST_BOXES;
		     ++i, ++bu)
		{
			b = bu->lkb_bu_box;

			if (b)
			{
				if (down_interruptible(&b->lkb_b_lock) < 0)
				{
					arraysize = 0;
					status = -EINTR;
				}
				else
				{
					if (lockbox_getselectstate(bu, b) == 2)
					{
						if (put_user(i, array) < 0)
						{
							arraysize = 0;
							status = -EFAULT;
						}
						else
						{
							++status;
							--arraysize;
						}
					}
					up(&b->lkb_b_lock);
				}
			}
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static int
lockbox_resetallselects(	lockbox_perfile *pf)
{
	lockbox_boxlist *bl;
	int	i;

	if (down_interruptible(&pf->lkb_pf_lock))
		return -EINTR;

	for (i = 0; i < IN_PERFILE_BOXES; ++i)
	{
		if (pf->lkb_pf_boxes[i].lkb_bu_box)
			reset_boxuse_selects(pf->lkb_pf_boxes + i);
	}

	for (bl = pf->lkb_pf_boxlist; bl; bl = bl->lkb_bl_next)
	{
		for (i = 0; i < IN_BOXLIST_BOXES; ++i)
		{
			if (bl->lkb_bl_boxes[i].lkb_bu_box)
				reset_boxuse_selects(bl->lkb_bl_boxes + i);
		}
	}
	up(&pf->lkb_pf_lock);
	return 0;
}

static int
lockbox_createselectfd(lockbox_perfile *pf,
			lockbox_select_fd_entry const *entries,
			size_t count,
			int	targetfd)
{
	int	i;
	struct file *f;
	lockbox_perfile *pfNew;
	int	status;
	lockbox_box *b;
	lockbox_boxuse *bu;
	lockbox_boxlist *bl;

	if (!pf->lkb_pf_vault)
		return -EINVAL;

	if (down_interruptible(&pf->lkb_pf_lock))
		return -EINTR;

	f = fget(targetfd);
	if (!f)
	{
		up(&pf->lkb_pf_lock);
		return -ENOENT;
	}

	pfNew = f->private_data;

	if (!is_lockbox_file(f) ||
	    !pfNew)
	{
		fput(f);
		up(&pf->lkb_pf_lock);
		return -EINVAL;
	}

	if (down_interruptible(&pfNew->lkb_pf_lock))
	{
		fput(f);
		up(&pf->lkb_pf_lock);
		return -EINTR;
	}

	status = 0;

	if (pfNew->lkb_pf_vault)
	{
		fput(f);
		down(&pfNew->lkb_pf_lock);
		down(&pf->lkb_pf_lock);
		status = -EINVAL;
	}
	else if (down_interruptible(&vaultlist_lock))
	{
		status = -EINTR;
	}
	else
	{
		/* Now we have a target file with no vault, which means it also has
		 * no lockboxes in it.
		 */
		pfNew->lkb_pf_vault = pf->lkb_pf_vault;
		++pf->lkb_pf_vault->lkb_v_users;
		up(&vaultlist_lock);

		while (!status && count--)
		{
			lockbox_select_fd_entry e;

			if (copy_from_user(&e, entries, sizeof(lockbox_select_fd_entry)))
			{
				status = -EFAULT;
				break;
			}
			++entries;

			status = lockbox_find_box(pf, e.lsfe_id, &bu);

			if (status < 0)
				break;

			b = bu->lkb_bu_box;

			if (down_interruptible(&b->lkb_b_lock))
			{
				status = -EINTR;
				break;
			}

			status = add_box_to_perfile(pfNew, b, 1);

			if (status >= 0)
				++b->lkb_b_users;
			up(&b->lkb_b_lock);
			if (status < 0)
				break;

			status = lockbox_find_box(pfNew, e.lsfe_id, &bu);
			if (status < 0)
				break;

			status = 0;

			while (e.lsfe_criteria--)
			{
				lockbox_select_criterion_setting s;

				if (copy_from_user(&s, e.lsfe_settings, sizeof(s)))
				{
					status = -EFAULT;
					break;
				}
				++e.lsfe_settings;
				status = set_criterion(bu, s.lscs_criterion, s.lscs_value);
				if (status < 0)
					break;
			}
		}
	}

	fput(f);
	up(&pf->lkb_pf_lock);

	/* Now we want to wake all sleepers on all boxes in the new fd due to the
	 * increased user count, but only if we succeeded, because if we didn't then
	 * the caller will free the file descriptor anyway so the increased user
	 * count on the boxes will soon drop, which will effect the wakeup anyway.
	 */

	if (!status)
	{
		for (i = 0, bu = pfNew->lkb_pf_boxes;
		     i < IN_PERFILE_BOXES;
		     ++i, ++bu)
		{
			b = bu->lkb_bu_box;

			if (b)
				wake_box_sleepers(b, 0);
		}

		for (bl = pfNew->lkb_pf_boxlist; bl; bl = bl->lkb_bl_next)
		{
			for (i = 0, bu = bl->lkb_bl_boxes;
			     i < IN_BOXLIST_BOXES;
			     ++i, ++bu)
			{
				b = bu->lkb_bu_box;

				if (b)
					wake_box_sleepers(b, 0);
			}
		}
	}

	up(&pfNew->lkb_pf_lock);

	return status;
}

static int
open_lockbox(	struct inode * inode,
		struct file * file)
{
	lockbox_perfile *perfile = kmalloc(sizeof(lockbox_perfile), GFP_KERNEL);

	if (!perfile)
		return -ENOMEM;

	memset(perfile, 0, sizeof(lockbox_perfile));
	init_MUTEX(&perfile->lkb_pf_lock);
	file->private_data = perfile;
	return 0;
}

static int
close_lockbox(	struct inode * inode,
		struct file * file)
{
	if (file->private_data)
		free_perfile(file->private_data);
	file->private_data = 0;
	return 0;
}

static ssize_t
write_lockbox(	struct file * file,
		const char * buffer,
		size_t count, loff_t *ppos)
{
	return -EIO;
}

static ssize_t
read_lockbox(	struct file * file,
		char * buffer,
		size_t count,
		loff_t *ppos)
{
	return -EIO;
}

static int
ioctl_lockbox(struct inode *inode, struct file *file,
	      unsigned int cmd, unsigned long arg)
{
	uint32_t	callid;
	lockbox_perfile *pf = file->private_data;

	if (cmd != LOCKBOX_IOCTL_CALL)
		return -EINVAL;
	if (get_user(callid, (uint32_t *)arg) < 0)
		return -EFAULT;
	switch(callid)
	{
	case LKBCALL_SETVAULT:
		{
			lockbox_setvault_struct s;

			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				return -EFAULT;
			return set_vault(pf, s.name);
		}

	case LKBCALL_LISTVAULTS:
		{
			int status;
			lockbox_listvaults_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			status = list_vaults(s.data, s.bufsize, &s.sizeneeded);
			if (copy_to_user((void *)arg, &s, sizeof(s)))
				return -EFAULT;
			return status;
		}

	case LKBCALL_CREATE:
		{
			lockbox_create_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_create_new(	pf,
							s.shelfid,
							s.name,
							s.data,
							s.size,
							s.acl);
		}

	case LKBCALL_OPEN:
		{
			lockbox_open_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_open_existing(	pf,
							s.shelfid,
							s.name);
		}

	case LKBCALL_CLOSE:
		{
			lockbox_close_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_close_box(pf, s.lockboxid);
		}

	case LKBCALL_GETNAME:
		{
			lockbox_getname_struct s;
			int	status;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			status = lockbox_get_name(pf,
						s.lockboxid,
						s.name,
						s.bufsize,
						&s.sizeneeded);
			if (copy_to_user((void *) arg, &s, sizeof(s)))
				return -EFAULT;
			return status;
		}

	case LKBCALL_LISTBOXES:
		{
			lockbox_listboxes_struct s;
			int	status;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			status = lockbox_list_boxes(pf,
						s.shelfid,
						s.names,
						s.bufsize,
						&s.sizeneeded);
			if (copy_to_user((void *) arg, &s, sizeof(s)))
				return -EFAULT;
			return status;
		}

	case LKBCALL_SIZE:
		{
			lockbox_size_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_size(pf, s.lockboxid);
		}

	case LKBCALL_GETDATA:
		{
			lockbox_getdata_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_get_data(pf, s.lockboxid, s.buffer, s.size, s.offset);
		}

	case LKBCALL_SETDATA:
		{
			lockbox_setdata_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_set_data(pf, s.lockboxid, s.buffer, s.size, s.offset);
		}

	case LKBCALL_SETSTATE:
		{
			lockbox_getsetstate_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_set_state(pf, s.lockboxid, s.state);
		}

	case LKBCALL_GETSTATE:
		{
			lockbox_getsetstate_struct s;
			int	status;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			status = lockbox_get_state(pf, s.lockboxid, &s.state);
			if (status >= 0 &&
			    copy_to_user((void *) arg, &s, sizeof(s)))
				return -EFAULT;
			return status;
		}

	case LKBCALL_GETUSERS:
		{
			lockbox_getsetstate_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_get_users(pf, s.lockboxid);
		}

	case LKBCALL_SETACL:
		{
			lockbox_setacl_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_set_acl(pf, s.lockboxid, s.acl);
		}

	case LKBCALL_GETACL:
		{
			lockbox_getacl_struct s;
			int status;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			status = lockbox_get_acl(pf, s.lockboxid,
						s.acl,
						s.size,
						&s.sizeneeded);
			if (copy_to_user((void *) arg, &s, sizeof(s)))
				return -EFAULT;
			return status;
		}

	case LKBCALL_SETFILE:
		{
			lockbox_setfile_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_set_file(pf, s.lockboxid, s.fd);
		}

	case LKBCALL_GETFILE:
		{
			lockbox_setfile_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_get_file(pf, s.lockboxid);
		}

	case LKBCALL_LOCK:
		{
			lockbox_lock_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_lock(pf, s.lockboxid, s.flags);
		}

	case LKBCALL_UNLOCK:
		{
			lockbox_lock_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_unlock(pf, s.lockboxid);
		}

	case LKBCALL_SETSELC:
		{
			lockbox_setselectcriterion_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_setselectcriterion(pf, s.lockboxid, s.type, s.value);
		}

	case LKBCALL_GETSELBOXES:
		{
			lockbox_getselectableboxes_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_getselectableboxes(pf, s.array, s.arraysize);
		}

	case LKBCALL_RSTSELCS:
		{
			return lockbox_resetallselects(pf);
		}

	case LKBCALL_CREATESELFD:
		{
			lockbox_createselectfd_struct s;

			if (copy_from_user(&s, (void *) arg, sizeof(s)))
				return -EFAULT;
			return lockbox_createselectfd(pf, s.entries, s.count, s.targetfd);
		}

	default:
		return -EINVAL;
	}
	return 0;
}

static int
check_select_attributes(lockbox_boxuse *bu,
			struct file	*f,
			struct poll_table_struct *pt)
{
	int	state;
	lockbox_box *b = bu->lkb_bu_box;

	if (!b)
		return 0;

	down(&b->lkb_b_lock);

	state = lockbox_getselectstate(bu, b);

	if (state == 1)
		poll_wait(f, &b->lkb_b_waitq, pt);
	up(&b->lkb_b_lock);

	return state == 2;
}

static unsigned int
poll_lockbox(	struct file *f,
		struct poll_table_struct *pt)
{
	lockbox_perfile *pf = (lockbox_perfile *) f->private_data;
	lockbox_boxlist *bl;
	unsigned int status = 0;
	int	i;

	if (!pf)
		return 0;
	down(&pf->lkb_pf_lock);

	for (i = 0; i < IN_PERFILE_BOXES; ++i)
	{
		if (check_select_attributes(pf->lkb_pf_boxes + i, f, pt))
		{
			status = POLLIN | POLLPRI;
			break;
		}
			
	}

	for (bl = pf->lkb_pf_boxlist; bl && !status; bl = bl->lkb_bl_next)
	{
		for (i = 0; i < IN_BOXLIST_BOXES; ++i)
		{
			if (check_select_attributes(bl->lkb_bl_boxes +
							i,
							f,
							pt))
			{
				status = POLLIN | POLLPRI;
				break;
			}
		}
	}
	up(&pf->lkb_pf_lock);
	return status;
}

static struct
file_operations lockbox_fops = {
	read:		read_lockbox,
	write:		write_lockbox,
	ioctl:		ioctl_lockbox,
	open:		open_lockbox,
	release:	close_lockbox,
	poll:		poll_lockbox
};

static int
is_lockbox_file(struct file *f)
{
	return (f->f_op == &lockbox_fops);
}

void __exit
lockbox_exit (void)
{
	remove_proc_entry("lockbox", 0);
	printk("lockbox driver unregistered\n");
}

int __init
lockbox_init (void)
{
	struct proc_dir_entry *pentry;

	pentry = create_proc_entry("lockbox", S_IFREG | S_IRUGO | S_IWUGO, 0);

	init_MUTEX(&vaultlist_lock);

	if (!pentry)
	{
		printk("lockbox: Could not create proc entry\n");
		return -1;
	}

	pentry->proc_fops = &lockbox_fops;
	pentry->owner = THIS_MODULE;
	printk("lockbox driver registered\n");
	return 0;
}

module_init(lockbox_init);
module_exit(lockbox_exit);
#define KERNEL
