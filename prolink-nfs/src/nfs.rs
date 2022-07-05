#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    unused_assignments,
    deprecated
)]
pub(super) mod xdr {
    use xdr_codec;
    include!(concat!(env!("OUT_DIR"), "/nfs_xdr.rs"));
}

pub const NFSPROG: u32 = 100003;
pub const NFSVER: u32 = 2;

#[repr(u32)]
enum NfsProc {
    NULL = 0,
    GETATTR = 1,
    SETATTR = 2,
    ROOT = 3,
    LOOKUP = 4,
    READLINK = 5,
    READ = 6,
    WRITE_CACHE = 7,
    WRITE = 8,
    CREATE = 9,
    REMOVE = 10,
    RENAME = 11,
    LINK = 12,
    SYMLINK = 13,
    MKDIR = 14,
    RMDIR = 15,
    READDIR = 16,
    STATFS = 17,
}
