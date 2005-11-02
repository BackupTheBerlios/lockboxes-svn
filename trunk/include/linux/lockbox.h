#define LOCKBOX_IOCTL_CALL _IOW('U', 0x20, int)

#ifndef __x86_64__

#define	LKBCALL_SETVAULT	1
#define	LKBCALL_LISTVAULTS	2
#define	LKBCALL_LISTBOXES	3
#define	LKBCALL_CREATE		4
#define	LKBCALL_OPEN		5
#define	LKBCALL_CLOSE		6
#define	LKBCALL_LOCK		7
#define	LKBCALL_UNLOCK		8
#define	LKBCALL_GETNAME		9
#define	LKBCALL_SIZE		10
#define	LKBCALL_GETDATA		11
#define	LKBCALL_SETDATA		12
#define	LKBCALL_SETSTATE	13
#define	LKBCALL_GETSTATE	14
#define	LKBCALL_SETFILE		15
#define	LKBCALL_GETFILE		16
#define	LKBCALL_SETACL		17
#define	LKBCALL_GETACL		18
#define	LKBCALL_SETSELC		19
#define	LKBCALL_GETSELBOXES	20
#define	LKBCALL_RSTSELCS	21
#define	LKBCALL_GETUSERS	22
#define	LKBCALL_CREATESELFD	23

#else

#define	LKBCALL32_SETVAULT	1
#define	LKBCALL32_LISTVAULTS	2
#define	LKBCALL32_LISTBOXES	3
#define	LKBCALL32_CREATE	4
#define	LKBCALL32_OPEN		5
#define	LKBCALL_CLOSE		6
#define	LKBCALL_LOCK		7
#define	LKBCALL_UNLOCK		8
#define	LKBCALL32_GETNAME	9
#define	LKBCALL_SIZE		10
#define	LKBCALL32_GETDATA	11
#define	LKBCALL32_SETDATA	12
#define	LKBCALL_SETSTATE	13
#define	LKBCALL_GETSTATE	14
#define	LKBCALL_SETFILE		15
#define	LKBCALL_GETFILE		16
#define	LKBCALL32_SETACL	17
#define	LKBCALL32_GETACL	18
#define	LKBCALL_SETSELC		19
#define	LKBCALL32_GETSELBOXES	20
#define	LKBCALL_RSTSELCS	21
#define	LKBCALL_GETUSERS	22
#define	LKBCALL32_CREATESELFD	23
#define	LKBCALL_SETVAULT	24
#define	LKBCALL_LISTVAULTS	25
#define	LKBCALL_LISTBOXES	26
#define	LKBCALL_CREATE		27
#define	LKBCALL_OPEN		28
#define	LKBCALL_GETNAME		29
#define	LKBCALL_GETDATA		30
#define	LKBCALL_SETDATA		31
#define	LKBCALL_SETACL		32
#define	LKBCALL_GETACL		33
#define	LKBCALL_GETSELBOXES	34
#define	LKBCALL_CREATESELFD	35

#endif

#include "../lockbox.h"

typedef struct
{
	uint32_t	callid;
	char	const	*name;
} lockbox_setvault_struct;

typedef struct
{
	uint32_t	callid;
	char		*data;
	size_t		bufsize;
	size_t		sizeneeded;
} lockbox_listvaults_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	shelfid;
	char		*names;
	size_t		bufsize;
	size_t		sizeneeded;
} lockbox_listboxes_struct;

typedef struct
{
	uint32_t	callid;
	int32_t		shelfid;
	char const	*name;
	char const	*data;
	size_t		size;
	lockbox_acl const *acl;
} lockbox_create_struct;

typedef struct
{
	uint32_t	callid;
	int32_t		shelfid;
	char const	*name;
} lockbox_open_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
} lockbox_close_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	flags;
} lockbox_lock_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
} lockbox_unlock_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	char		*name;
	size_t		bufsize;
	size_t		sizeneeded;
} lockbox_getname_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
} lockbox_size_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	void		*buffer;
	size_t		size;
	off_t		offset;
} lockbox_getdata_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	void		const *buffer;
	size_t		size;
	off_t		offset;
} lockbox_setdata_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	state;
} lockbox_getsetstate_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	int		fd;
} lockbox_setfile_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
} lockbox_getfile_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
} lockbox_getusers_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	lockbox_acl const *acl;
} lockbox_setacl_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	lockbox_acl 	*acl;
	size_t		size;
	size_t		sizeneeded;
} lockbox_getacl_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	type;
	uint32_t	value;
} lockbox_setselectcriterion_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	arraysize;
	lockbox_t	*array;
} lockbox_getselectableboxes_struct;

typedef struct
{
	uint32_t	callid;
} lockbox_resetallselects_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_select_fd_entry const *entries;
	size_t		count;
	int		targetfd;
} lockbox_createselectfd_struct;

#ifdef __x86_64__

typedef struct
{
	uint32_t	callid;
	uint32_t	name;
} lockbox32_setvault_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	data;
	uint32_t	bufsize;
	uint32_t	sizeneeded;
} lockbox32_listvaults_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	shelfid;
	uint32_t	names;
	uint32_t	bufsize;
	uint32_t	sizeneeded;
} lockbox32_listboxes_struct;

typedef struct
{
	uint32_t	callid;
	int32_t		shelfid;
	uint32_t	name;
	uint32_t	data;
	uint32_t	size;
	uint32_t 	acl;
} lockbox32_create_struct;

typedef struct
{
	uint32_t	callid;
	int32_t		shelfid;
	uint32_t	name;
} lockbox32_open_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	name;
	uint32_t	bufsize;
	uint32_t	sizeneeded;
} lockbox32_getname_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	buffer;
	uint32_t	size;
	uint32_t	offset;
} lockbox32_getdata_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	buffer;
	uint32_t	size;
	uint32_t	offset;
} lockbox32_setdata_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	acl;
} lockbox32_setacl_struct;

typedef struct
{
	uint32_t	callid;
	lockbox_t	lockboxid;
	uint32_t	acl;
	uint32_t	size;
	uint32_t	sizeneeded;
} lockbox32_getacl_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	arraysize;
	uint32_t	array;
} lockbox32_getselectableboxes_struct;

typedef struct
{
	uint32_t	callid;
	uint32_t	entries;
	uint32_t	count;
	int		targetfd;
} lockbox32_createselectfd_struct;

#endif
