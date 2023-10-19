/* minimal spec for dsniff's decode_mountd(). */

/*
 * Copyright (c) 1988,1990,1991,1992 by Sun Microsystems, Inc.
 */

/*
 * Protocol description for the mount program
 */

const MNTPATHLEN = 1024;	/* maximum bytes in a pathname argument */
const MNTNAMLEN = 255;		/* maximum bytes in a name argument */
const FHSIZE = 32;		/* size in bytes of a v2 file handle */
const FHSIZE3 = 64;		/*  "   "    "   "  " v3  "     "    */

/*
 * The fhandle is the file handle that the server passes to the client.
 * All file operations are done using the file handles to refer to a file
 * or a directory. The file handle can contain whatever information the
 * server needs to distinguish an individual file.
 *
 * Versions 1 and 2 of the protocol share a filehandle of 32 bytes.
 *
 * Version 3 supports a 64 byte filehandle that can be used only
 * with version 3 of the NFS protocol.
 */

typedef opaque fhandle[FHSIZE];
typedef opaque fhandle3<FHSIZE3>;

/*
 * If a V2 status of zero is returned, the call completed successfully, and
 * a file handle for the directory follows. A non-zero status indicates
 * some sort of error. The status corresponds with UNIX error numbers.
 */
union fhstatus switch (unsigned fhs_status) {
case 0:
	fhandle fhs_fhandle;
default:
	void;
};

/*
 * This #define is added for backwards compatability with applications
 * which reference the old style fhstatus.  The second element of that
 * structure was called fhs_fh, instead of the current fhs_fhandle.
 */
%
%#define	fhs_fh	fhstatus_u.fhs_fhandle

/*
 * The following status codes are defined for the V3 mount service:
 * Note that the precise enum encoding must be followed; the values
 * are derived from existing implementation practice, and there is
 * no good reason to disturb them.
 */
enum mountstat3 {
        MNT_OK= 0,              /* no error */
        MNT3ERR_PERM=1,         /* Not owner */
        MNT3ERR_NOENT=2,        /* No such file or directory */
        MNT3ERR_IO=5,           /* I/O error */
        MNT3ERR_ACCES=13,       /* Permission denied */
        MNT3ERR_NOTDIR=20,      /* Not a directory*/
        MNT3ERR_INVAL=22,       /* Invalid argument.*/
        MNT3ERR_NAMETOOLONG=63, /* File name too long */
        MNT3ERR_NOTSUPP=10004,  /* operation not supported */
        MNT3ERR_SERVERFAULT=10006 /* An i/o or similar failure caused */
                                /* the server to abandon the request */
                                /* No attributes can be returned. The */
                                /* client should translate this into EIO */
};

/*
 * A V3 server returns a file handle and a list of the authentication
 * flavors that the server will accept for this mount.  If the list
 * is empty, AUTH_UNIX is required.  Otherwise, any of the flavors
 * listed in auth_flavors<> may be used (but no others).
 * The values of the authentication flavors are defined in the
 * underlying RPC protocol.
 */
struct mountres3_ok {
	fhandle3 fhandle;
	int auth_flavors<>;
};

/*
 * If a V3 status of MNT_OK is returned, the call completed successfully, and
 * a file handle for the directory follows. Any other status indicates
 * some sort of error.
 */

union mountres3 switch (mountstat3 fhs_status) {
case MNT_OK:
        mountres3_ok mountinfo;
default:
        void;
};

/*
 * The type dirpath is the pathname of a directory
 */
typedef string dirpath<MNTPATHLEN>;

program MOUNTPROG {
	/*
	 * Version one of the mount protocol communicates with version two
	 * of the NFS protocol. The only connecting point is the fhandle
	 * structure, which is the same for both protocols.
	 */
	version MOUNTVERS {
		/*
		 * Does no work. It is made available in all RPC services
		 * to allow server reponse testing and timing
		 */
		void
		MOUNTPROC_NULL(void) = 0;

		/*
		 * If fhs_status is 0, then fhs_fhandle contains the
	 	 * file handle for the directory. This file handle may
		 * be used in the NFS protocol. This procedure also adds
		 * a new entry to the mount list for this client mounting
		 * the directory.
		 * Unix authentication required.
		 */
		fhstatus
		MOUNTPROC_MNT(dirpath) = 1;
	} = 1;

	/*
	 * Version two of the mount protocol communicates with version two
	 * of the NFS protocol. It is identical to version one except for a
	 * new procedure call for posix.
	 */
	version MOUNTVERS_POSIX {
		/*
		 * Does no work. It is made available in all RPC services
		 * to allow server reponse testing and timing
		 */
		void
		MOUNTPROC_NULL(void) = 0;

		/*
		 * If fhs_status is 0, then fhs_fhandle contains the
	 	 * file handle for the directory. This file handle may
		 * be used in the NFS protocol. This procedure also adds
		 * a new entry to the mount list for this client mounting
		 * the directory.
		 * Unix authentication required.
		 */
		fhstatus
		MOUNTPROC_MNT(dirpath) = 1;
	} = 2;

	/*
	 * Version 3 of the mount protocol communicates with version 3
	 * of the NFS protocol. The only connecting point is the nfs_fh3
	 * structure, which is the same for both protocols.
	 *
	 * The only significant change over version 2 is that MOUNTPROC_MNT
	 * returns a longer filehandle (64 bytes instead of 32) as well
	 * as authentication information.  MOUNTPROC_PATHCONF is subsumed
	 * into V3 of the NFS protocol and MOUNTPROC_EXPORTALL is eliminated.
	 */
	version MOUNTVERS3 {
		/*
		 * Does no work. It is made available in all RPC services
		 * to allow server reponse testing and timing
		 */
		void
		MOUNTPROC_NULL(void) = 0;

		/*
		 * Mount a file system.
		 *
		 * If mountres.fhs_status is NFS_OK, then mountres.mountinfo
		 * contains the file handle for the directory and
		 * a list of acceptable authentication flavors. This file
		 * handle may only be used in version 3 of the NFS protocol.
		 * This procedure also results in the server adding a new
		 * entry to its mount list recording that this client has
		 * mounted the directory. Unix authentication or better
		 * is required.
		 */
		mountres3
		MOUNTPROC_MNT(dirpath) = 1;
	} = 3;
} = 100005;
