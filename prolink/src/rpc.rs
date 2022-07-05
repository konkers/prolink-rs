mod xdr {
    //! An auto-generated set of NFS wire types.
    //!
    //! Do NOT modify the generated file directly.

    #![allow(non_camel_case_types, dead_code, unused_mut, unreachable_patterns)]

    use bytes::{Buf, Bytes};
    use std::convert::TryFrom;
    use std::fmt::Debug;
    use std::mem::size_of;
    use thiserror::Error;

    #[derive(Debug, Error, PartialEq)]
    pub enum Error {
        #[error("invalid message length")]
        InvalidLength,

        #[error("non-utf8 characters in string: {0}")]
        NonUtf8String(#[from] std::string::FromUtf8Error),

        #[error("invalid boolean value")]
        InvalidBoolean,

        #[error("unknown enum variant {0}")]
        UnknownVariant(i32),

        #[error("unknown option variant {0}")]
        UnknownOptionVariant(u32),

        #[error("{0}")]
        Unknown(String),
    }

    pub trait DeserialiserExt {
        type Sliced: WireSize + IntoIterator<Item = u8>;
        type TryFrom;

        fn try_u32(&mut self) -> Result<u32, Error>;
        fn try_u64(&mut self) -> Result<u64, Error>;
        fn try_i32(&mut self) -> Result<i32, Error>;
        fn try_i64(&mut self) -> Result<i64, Error>;
        fn try_f32(&mut self) -> Result<f32, Error>;
        fn try_f64(&mut self) -> Result<f64, Error>;
        fn try_bool(&mut self) -> Result<bool, Error>;
        fn try_bytes(&mut self, n: usize) -> Result<Self::Sliced, Error>;
        fn try_variable_array<T>(&mut self, max: Option<usize>) -> Result<Vec<T>, Error>
        where
            T: TryFrom<Self::TryFrom, Error = Error> + WireSize;

        /// Try to read an opaque XDR array, prefixed by a length u32 and padded
        /// modulo 4.
        fn try_variable_bytes(&mut self, max: Option<usize>) -> Result<Self::Sliced, Error> {
            let n = self.try_u32()? as usize;

            if let Some(limit) = max {
                if n > limit {
                    return Err(Error::InvalidLength);
                }
            }

            self.try_bytes(n)
        }

        /// Reads a variable length UTF8-compatible string from the buffer.
        fn try_string(&mut self, max: Option<usize>) -> Result<String, Error> {
            let b = self
                .try_variable_bytes(max)?
                .into_iter()
                .collect::<Vec<u8>>();
            String::from_utf8(b).map_err(|e| e.into())
        }
    }

    impl DeserialiserExt for Bytes {
        type Sliced = Self;
        type TryFrom = Bytes;

        // Try and read a u32 if self contains enough data.
        fn try_u32(&mut self) -> Result<u32, Error> {
            if self.remaining() < size_of::<u32>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_u32())
        }

        fn try_u64(&mut self) -> Result<u64, Error> {
            if self.remaining() < size_of::<u64>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_u64())
        }

        fn try_i32(&mut self) -> Result<i32, Error> {
            if self.remaining() < size_of::<i32>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_i32())
        }

        fn try_i64(&mut self) -> Result<i64, Error> {
            if self.remaining() < size_of::<i64>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_i64())
        }

        fn try_f32(&mut self) -> Result<f32, Error> {
            if self.remaining() < size_of::<f32>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_f32())
        }

        fn try_f64(&mut self) -> Result<f64, Error> {
            if self.remaining() < size_of::<f64>() {
                return Err(Error::InvalidLength);
            }
            Ok(self.get_f64())
        }

        fn try_bool(&mut self) -> Result<bool, Error> {
            if self.remaining() < size_of::<i32>() {
                return Err(Error::InvalidLength);
            }
            match self.get_i32() {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::InvalidBoolean),
            }
        }

        /// Try to read an opaque XDR array with a fixed length and padded modulo 4.
        fn try_bytes(&mut self, n: usize) -> Result<Self::Sliced, Error> {
            // Validate the buffer contains enough data
            if self.remaining() < n {
                return Err(Error::InvalidLength);
            }

            let data = self.slice(..n);

            // Advance the buffer cursor, including any padding.
            self.advance(n + pad_length(n));

            Ok(data)
        }

        fn try_variable_array<T>(&mut self, max: Option<usize>) -> Result<Vec<T>, Error>
        where
            T: TryFrom<Self, Error = Error> + WireSize,
        {
            let n = self.try_u32()? as usize;

            if let Some(limit) = max {
                if n > limit {
                    return Err(Error::InvalidLength);
                }
            }

            // Try and decode n instances of T.
            let mut sum = 0;
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let t = T::try_from(self.clone())?;
                if self.remaining() < t.wire_size() {
                    return Err(Error::InvalidLength);
                }
                self.advance(t.wire_size());
                sum += t.wire_size();
                out.push(t);
            }

            self.advance(pad_length(sum));

            Ok(out)
        }
    }

    pub trait WireSize {
        fn wire_size(&self) -> usize;
    }

    impl WireSize for Bytes {
        fn wire_size(&self) -> usize {
            self.len()
        }
    }

    impl<T> WireSize for Vec<T>
    where
        T: WireSize,
    {
        fn wire_size(&self) -> usize {
            // Element count prefix of 4 bytes, plus the individual element lengths
            // (which may vary between elements).
            let x = self.iter().map(|v| v.wire_size()).sum::<usize>();
            4 + x + pad_length(x)
        }
    }

    impl<T> WireSize for [T]
    where
        T: WireSize,
    {
        fn wire_size(&self) -> usize {
            // Individual element lengths (which may vary between elements) without
            // a length byte as [T] is for fixed size arrays.
            let x = self.iter().map(|v| v.wire_size()).sum::<usize>();
            x + pad_length(x)
        }
    }

    impl<T> WireSize for Option<T>
    where
        T: WireSize,
    {
        fn wire_size(&self) -> usize {
            4 + match self {
                Some(inner) => inner.wire_size(),
                None => 0,
            }
        }
    }

    impl<T> WireSize for Box<T>
    where
        T: WireSize,
    {
        fn wire_size(&self) -> usize {
            use std::ops::Deref;
            self.deref().wire_size()
        }
    }

    impl WireSize for u8 {
        fn wire_size(&self) -> usize {
            1
        }
    }

    impl WireSize for u32 {
        fn wire_size(&self) -> usize {
            4
        }
    }

    impl WireSize for i32 {
        fn wire_size(&self) -> usize {
            4
        }
    }

    impl WireSize for u64 {
        fn wire_size(&self) -> usize {
            8
        }
    }

    impl WireSize for i64 {
        fn wire_size(&self) -> usize {
            8
        }
    }

    impl WireSize for f32 {
        fn wire_size(&self) -> usize {
            4
        }
    }

    impl WireSize for f64 {
        fn wire_size(&self) -> usize {
            8
        }
    }

    impl WireSize for bool {
        fn wire_size(&self) -> usize {
            4
        }
    }

    impl WireSize for String {
        fn wire_size(&self) -> usize {
            4 + self.len() + pad_length(self.len())
        }
    }

    #[inline]
    fn pad_length(l: usize) -> usize {
        if l % 4 == 0 {
            return 0;
        }
        4 - (l % 4)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use bytes::{BufMut, BytesMut};

        #[derive(Debug, PartialEq)]
        struct TestStruct {
            a: u32,
        }

        impl TryFrom<Bytes> for TestStruct {
            type Error = Error;

            fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
                Ok(Self { a: v.try_u32()? })
            }
        }

        impl WireSize for TestStruct {
            fn wire_size(&self) -> usize {
                self.a.wire_size()
            }
        }

        #[derive(Debug, PartialEq)]
        struct VariableSizedStruct {
            a: Vec<u32>,
        }

        impl TryFrom<Bytes> for VariableSizedStruct {
            type Error = Error;

            fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
                // Stub, always has a len of 2
                let x = v.try_u32()?;
                if x != 2 {
                    panic!("expected len of 2, got {}", x);
                }
                Ok(Self {
                    a: vec![v.try_u32()?, v.try_u32()?],
                })
            }
        }

        impl WireSize for VariableSizedStruct {
            fn wire_size(&self) -> usize {
                self.a.wire_size()
            }
        }

        #[derive(Debug, PartialEq)]
        struct UnalignedStruct {
            a: u8,
        }

        impl TryFrom<Bytes> for UnalignedStruct {
            type Error = Error;

            fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
                let s = v.slice(..1);
                v.advance(1);
                Ok(Self { a: s.as_ref()[0] })
            }
        }

        impl WireSize for UnalignedStruct {
            fn wire_size(&self) -> usize {
                1
            }
        }

        #[test]
        fn test_pad_length() {
            assert_eq!(pad_length(0), 0);
            assert_eq!(pad_length(1), 3);
            assert_eq!(pad_length(2), 2);
            assert_eq!(pad_length(3), 1);
            assert_eq!(pad_length(4), 0);
        }

        #[test]
        fn test_wire_size_basic_types() {
            assert_eq!((42 as u8).wire_size(), 1);
            assert_eq!((42 as u32).wire_size(), 4);
            assert_eq!((42 as i32).wire_size(), 4);
            assert_eq!((42 as u64).wire_size(), 8);
            assert_eq!((42 as i64).wire_size(), 8);
            assert_eq!((42 as f32).wire_size(), 4);
            assert_eq!((42 as f64).wire_size(), 8);

            // Length prefix of 4 bytes, plus data 5 bytes, plus padding to mod 4
            assert_eq!(String::from("test!").wire_size(), 4 + 5 + 3);

            let mut b = Bytes::new();
            assert_eq!(b.wire_size(), 0);

            let b = BytesMut::new().freeze();
            assert_eq!(b.wire_size(), 0);

            let b = BytesMut::from("test").freeze();
            assert_eq!(b.wire_size(), 4);

            let b: &[u8] = &[1, 2, 3, 4];
            assert_eq!(b.wire_size(), 4);
        }

        #[test]
        fn test_wire_size_vec() {
            let v1: Vec<u32> = vec![1, 2, 3, 4];
            assert_eq!(v1.wire_size(), 4 * 5);

            let v2: Vec<u64> = vec![1, 2, 3, 4];
            assert_eq!(v2.wire_size(), (8 * 4) + 4);
        }

        #[test]
        fn test_wire_size_array() {
            let v1: [u32; 4] = [1, 2, 3, 4];
            assert_eq!(v1.wire_size(), 4 * 4);

            let v2: [u64; 4] = [1, 2, 3, 4];
            assert_eq!(v2.wire_size(), 8 * 4);
        }

        #[test]
        fn test_variable_array_variable_len_struct() {
            let mut buf = BytesMut::new();
            buf.put_u32(2); // 2 structs

            buf.put_u32(2); // This struct has 2 values
            buf.put_u32(1); // Struct 1
            buf.put_u32(2); // Struct 2

            buf.put_u32(2); // This struct has 2 values
            buf.put_u32(3); // Struct 1
            buf.put_u32(4); // Struct 2

            buf.put_u32(123); // Remaining buffer
            let mut buf = buf.freeze();

            let got = buf.try_variable_array::<VariableSizedStruct>(None).unwrap();

            assert_eq!(got.len(), 2);
            assert_eq!(
                got.wire_size(),
                4 + // Variable array length prefix

                4 + // First struct array length prefix
                8 + // First struct data

                4 + // Second struct array length prefix
                8 // Second struct data
            );
            assert_eq!(got[0], VariableSizedStruct { a: vec![1, 2] });

            assert_eq!(buf.len(), 4);
            assert_eq!(buf.as_ref(), &[0, 0, 0, 123]);
        }

        #[test]
        fn test_variable_array_no_max() {
            let mut buf = BytesMut::new();
            buf.put_u32(4); // Len=4
            buf.put_u8(1); // Struct 1
            buf.put_u8(2); // Struct 2
            buf.put_u8(3); // Struct 3
            buf.put_u8(4); // Struct 4
            buf.put_u32(123); // Remaining buffer
            let mut buf = buf.freeze();

            let got = buf.try_variable_array::<UnalignedStruct>(None).unwrap();

            assert_eq!(got.len(), 4);
            assert_eq!(got.wire_size(), 4 + 4); // Inner vecs + vec length

            assert_eq!(got[0], UnalignedStruct { a: 1 });
            assert_eq!(got[0].wire_size(), 1);

            assert_eq!(got[1], UnalignedStruct { a: 2 });
            assert_eq!(got[1].wire_size(), 1);

            assert_eq!(got[2], UnalignedStruct { a: 3 });
            assert_eq!(got[2].wire_size(), 1);

            assert_eq!(got[3], UnalignedStruct { a: 4 });
            assert_eq!(got[3].wire_size(), 1);

            assert_eq!(buf.len(), 4);
            assert_eq!(buf.as_ref(), &[0, 0, 0, 123]);
        }

        #[test]
        fn test_variable_array_no_max_with_padding() {
            let mut buf = BytesMut::new();
            buf.put_u32(2); // Len=4
            buf.put_u8(1); // Struct 1
            buf.put_u8(2); // Struct 2
            buf.put_u8(0); // Padding
            buf.put_u8(0); // Padding
            buf.put_u32(123); // Remaining buffer
            let mut buf = buf.freeze();

            let got = buf.try_variable_array::<UnalignedStruct>(None).unwrap();

            assert_eq!(got.len(), 2);
            assert_eq!(got.wire_size(), 4 + 4);
            assert_eq!(got[0], UnalignedStruct { a: 1 });
            assert_eq!(got[1], UnalignedStruct { a: 2 });

            assert_eq!(buf.len(), 4);
            assert_eq!(buf.as_ref(), &[0, 0, 0, 123]);
        }

        #[test]
        fn test_try_variable_bytes_no_max() {
            let mut buf = BytesMut::new();
            buf.put_u32(8); // Len=8
            buf.put([1, 2, 3, 4, 5, 6, 7, 8].as_ref());
            let mut buf = buf.freeze();

            let got = buf.try_variable_bytes(None).unwrap();

            assert_eq!(got.len(), 8);
            assert_eq!(got.wire_size(), 8);
            assert_eq!(got.as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);

            assert_eq!(buf.as_ref(), &[]);
            assert_eq!(buf.remaining(), 0);
        }

        #[test]
        fn test_try_variable_bytes_no_max_with_padding() {
            let mut buf = BytesMut::new();
            buf.put_u32(6); // Len=6 + 2 bytes padding
            buf.put([1, 2, 3, 4, 5, 6, 0, 0].as_ref());
            let mut buf = buf.freeze();

            let got = buf.try_variable_bytes(None).unwrap();

            assert_eq!(got.len(), 6);
            assert_eq!(got.wire_size(), 6);
            assert_eq!(got.as_ref(), &[1, 2, 3, 4, 5, 6]);

            assert_eq!(buf.as_ref(), &[]);
            assert_eq!(buf.remaining(), 0);
        }

        #[test]
        fn test_try_bool() {
            let mut buf = BytesMut::new();
            buf.put_u32(0);
            buf.put_u32(1);
            buf.put_u32(2);
            let mut buf = buf.freeze();

            assert_eq!(buf.try_bool(), Ok(false));
            assert_eq!(buf.try_bool(), Ok(true));
            assert!(buf.try_bool().is_err());
        }
    }
#[derive(Debug, PartialEq)]
pub enum accept_stat {
SUCCESS = 0,
PROG_UNAVAIL = 1,
PROG_MISMATCH = 2,
PROC_UNAVAIL = 3,
GARBAGE_ARGS = 4,
SYSTEM_ERR = 5,
}
#[derive(Debug, PartialEq)]
pub struct accepted_reply<T> where T: AsRef<[u8]> + Debug {
pub verf: opaque_auth,
pub data: reply_data<T>,
}
#[derive(Debug, PartialEq)]
pub enum auth_stat {
AUTH_OK = 0,
AUTH_BADCRED = 1,
AUTH_REJECTEDCRED = 2,
AUTH_BADVERF = 3,
AUTH_REJECTEDVERF = 4,
AUTH_TOOWEAK = 5,
AUTH_INVALIDRESP = 6,
AUTH_FAILED = 7,
AUTH_KERB_GENERIC = 8,
AUTH_TIMEEXPIRE = 9,
AUTH_TKT_FILE = 10,
AUTH_DECODE = 11,
AUTH_NET_ADDR = 12,
RPCSEC_GSS_CREDPROBLEM = 13,
RPCSEC_GSS_CTXPROBLEM = 14,
}
#[derive(Debug, PartialEq)]
pub struct call_body<T> where T: AsRef<[u8]> + Debug {
pub rpcvers: u32,
pub prog: u32,
pub vers: u32,
pub proc: u32,
pub cred: opaque_auth,
pub verf: opaque_auth,
pub params: T,
}
#[derive(Debug, PartialEq)]
pub struct mismatch {
pub low: u32,
pub high: u32,
}
#[derive(Debug, PartialEq)]
pub enum msg_body<T> where T: AsRef<[u8]> + Debug {
CALL(call_body<T>),
REPLY(reply_body<T>),
}
#[derive(Debug, PartialEq)]
pub enum msg_type {
CALL = 0,
REPLY = 1,
}
#[derive(Debug, PartialEq)]
pub enum reject_stat {
RPC_MISMATCH = 0,
AUTH_ERROR = 1,
}
#[derive(Debug, PartialEq)]
pub enum rejected_reply {
RPC_MISMATCH(mismatch),
AUTH_ERROR(auth_stat),
}
#[derive(Debug, PartialEq)]
pub enum reply_body<T> where T: AsRef<[u8]> + Debug {
MSG_ACCEPTED(accepted_reply<T>),
MSG_DENIED(rejected_reply),
}
#[derive(Debug, PartialEq)]
pub enum reply_data<T> where T: AsRef<[u8]> + Debug {
SUCCESS(results<T>),
PROG_MISMATCH(mismatch),
default,
}
#[derive(Debug, PartialEq)]
pub enum reply_stat {
MSG_ACCEPTED = 0,
MSG_DENIED = 1,
}
#[derive(Debug, PartialEq)]
pub struct results<T: AsRef<[u8]> + Debug>(pub T);
#[derive(Debug, PartialEq)]
pub struct rpc_msg<T> where T: AsRef<[u8]> + Debug {
pub xid: u32,
pub body: msg_body<T>,
}
impl TryFrom<Bytes> for accept_stat {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::SUCCESS,
1 => Self::PROG_UNAVAIL,
2 => Self::PROG_MISMATCH,
3 => Self::PROC_UNAVAIL,
4 => Self::GARBAGE_ARGS,
5 => Self::SYSTEM_ERR,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for accepted_reply<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(accepted_reply {
verf: opaque_auth::try_from(&mut v)?,
data: reply_data::try_from(&mut v)?,
})
}
}
impl TryFrom<Bytes> for auth_stat {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::AUTH_OK,
1 => Self::AUTH_BADCRED,
2 => Self::AUTH_REJECTEDCRED,
3 => Self::AUTH_BADVERF,
4 => Self::AUTH_REJECTEDVERF,
5 => Self::AUTH_TOOWEAK,
6 => Self::AUTH_INVALIDRESP,
7 => Self::AUTH_FAILED,
8 => Self::AUTH_KERB_GENERIC,
9 => Self::AUTH_TIMEEXPIRE,
10 => Self::AUTH_TKT_FILE,
11 => Self::AUTH_DECODE,
12 => Self::AUTH_NET_ADDR,
13 => Self::RPCSEC_GSS_CREDPROBLEM,
14 => Self::RPCSEC_GSS_CTXPROBLEM,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for call_body<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(call_body {
rpcvers: v.try_u32()?,
prog: v.try_u32()?,
vers: v.try_u32()?,
proc: v.try_u32()?,
cred: opaque_auth::try_from(&mut v)?,
verf: opaque_auth::try_from(&mut v)?,
params: v.try_variable_bytes(None)?,
})
}
}
impl TryFrom<Bytes> for mismatch {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(mismatch {
low: v.try_u32()?,
high: v.try_u32()?,
})
}
}
impl TryFrom<Bytes> for msg_body<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
let mtype = msg_type::try_from(&mut v)?;
Ok(match mtype {
msg_type::CALL => Self::CALL(call_body::try_from(&mut v)?),
msg_type::REPLY => Self::REPLY(reply_body::try_from(&mut v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for msg_type {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::CALL,
1 => Self::REPLY,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for reject_stat {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::RPC_MISMATCH,
1 => Self::AUTH_ERROR,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for rejected_reply {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
let stat = reject_stat::try_from(&mut v)?;
Ok(match stat {
reject_stat::RPC_MISMATCH => Self::RPC_MISMATCH(mismatch::try_from(&mut v)?),
reject_stat::AUTH_ERROR => Self::AUTH_ERROR(auth_stat::try_from(&mut v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for reply_body<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
let stat = reply_stat::try_from(&mut v)?;
Ok(match stat {
reply_stat::MSG_ACCEPTED => Self::MSG_ACCEPTED(accepted_reply::try_from(&mut v)?),
reply_stat::MSG_DENIED => Self::MSG_DENIED(rejected_reply::try_from(&mut v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for reply_data<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
let stat = accept_stat::try_from(&mut v)?;
Ok(match stat {
accept_stat::SUCCESS => Self::SUCCESS(results::try_from(&mut v)?),
accept_stat::PROG_MISMATCH => Self::PROG_MISMATCH(mismatch::try_from(&mut v)?),
_ => Self::default,
})
}
}
impl TryFrom<Bytes> for reply_stat {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::MSG_ACCEPTED,
1 => Self::MSG_DENIED,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<Bytes> for results<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(Self(v.try_variable_bytes(None)?))
}
}
impl TryFrom<Bytes> for rpc_msg<Bytes> {
type Error = Error;

fn try_from(mut v: Bytes) -> Result<Self, Self::Error> {
Ok(rpc_msg {
xid: v.try_u32()?,
body: msg_body::try_from(&mut v)?,
})
}
}
impl TryFrom<&mut Bytes> for accept_stat {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::SUCCESS,
1 => Self::PROG_UNAVAIL,
2 => Self::PROG_MISMATCH,
3 => Self::PROC_UNAVAIL,
4 => Self::GARBAGE_ARGS,
5 => Self::SYSTEM_ERR,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for accepted_reply<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(accepted_reply {
verf: opaque_auth::try_from(&mut *v)?,
data: reply_data::try_from(&mut *v)?,
})
}
}
impl TryFrom<&mut Bytes> for auth_stat {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::AUTH_OK,
1 => Self::AUTH_BADCRED,
2 => Self::AUTH_REJECTEDCRED,
3 => Self::AUTH_BADVERF,
4 => Self::AUTH_REJECTEDVERF,
5 => Self::AUTH_TOOWEAK,
6 => Self::AUTH_INVALIDRESP,
7 => Self::AUTH_FAILED,
8 => Self::AUTH_KERB_GENERIC,
9 => Self::AUTH_TIMEEXPIRE,
10 => Self::AUTH_TKT_FILE,
11 => Self::AUTH_DECODE,
12 => Self::AUTH_NET_ADDR,
13 => Self::RPCSEC_GSS_CREDPROBLEM,
14 => Self::RPCSEC_GSS_CTXPROBLEM,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for call_body<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(call_body {
rpcvers: v.try_u32()?,
prog: v.try_u32()?,
vers: v.try_u32()?,
proc: v.try_u32()?,
cred: opaque_auth::try_from(&mut *v)?,
verf: opaque_auth::try_from(&mut *v)?,
params: v.try_variable_bytes(None)?,
})
}
}
impl TryFrom<&mut Bytes> for mismatch {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(mismatch {
low: v.try_u32()?,
high: v.try_u32()?,
})
}
}
impl TryFrom<&mut Bytes> for msg_body<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
let mtype = msg_type::try_from(&mut *v)?;
Ok(match mtype {
msg_type::CALL => Self::CALL(call_body::try_from(&mut *v)?),
msg_type::REPLY => Self::REPLY(reply_body::try_from(&mut *v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for msg_type {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::CALL,
1 => Self::REPLY,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for reject_stat {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::RPC_MISMATCH,
1 => Self::AUTH_ERROR,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for rejected_reply {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
let stat = reject_stat::try_from(&mut *v)?;
Ok(match stat {
reject_stat::RPC_MISMATCH => Self::RPC_MISMATCH(mismatch::try_from(&mut *v)?),
reject_stat::AUTH_ERROR => Self::AUTH_ERROR(auth_stat::try_from(&mut *v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for reply_body<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
let stat = reply_stat::try_from(&mut *v)?;
Ok(match stat {
reply_stat::MSG_ACCEPTED => Self::MSG_ACCEPTED(accepted_reply::try_from(&mut *v)?),
reply_stat::MSG_DENIED => Self::MSG_DENIED(rejected_reply::try_from(&mut *v)?),
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for reply_data<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
let stat = accept_stat::try_from(&mut *v)?;
Ok(match stat {
accept_stat::SUCCESS => Self::SUCCESS(results::try_from(&mut *v)?),
accept_stat::PROG_MISMATCH => Self::PROG_MISMATCH(mismatch::try_from(&mut *v)?),
_ => Self::default,
})
}
}
impl TryFrom<&mut Bytes> for reply_stat {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(match v.try_i32()? {
0 => Self::MSG_ACCEPTED,
1 => Self::MSG_DENIED,
d => return Err(Error::UnknownVariant(d as i32)),
})
}
}
impl TryFrom<&mut Bytes> for results<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(Self(v.try_variable_bytes(None)?))
}
}
impl TryFrom<&mut Bytes> for rpc_msg<Bytes> {
type Error = Error;

fn try_from(mut v: &mut Bytes) -> Result<Self, Self::Error> {
Ok(rpc_msg {
xid: v.try_u32()?,
body: msg_body::try_from(&mut *v)?,
})
}
}
impl WireSize for accept_stat {
fn wire_size(&self) -> usize {
4
}
}
impl WireSize for accepted_reply<Bytes> {
fn wire_size(&self) -> usize {
self.verf.wire_size() +
self.data.wire_size() +
0
}
}
impl WireSize for auth_stat {
fn wire_size(&self) -> usize {
4
}
}
impl WireSize for call_body<Bytes> {
fn wire_size(&self) -> usize {
self.rpcvers.wire_size() +
self.prog.wire_size() +
self.vers.wire_size() +
self.proc.wire_size() +
self.cred.wire_size() +
self.verf.wire_size() +
self.params.wire_size() +
 pad_length(self.params.wire_size()) +
0
}
}
impl WireSize for mismatch {
fn wire_size(&self) -> usize {
self.low.wire_size() +
self.high.wire_size() +
0
}
}
impl WireSize for msg_body<Bytes> {
fn wire_size(&self) -> usize {
4 + match self {
Self::CALL(inner) => inner.wire_size(),
Self::REPLY(inner) => inner.wire_size(),
}
}
}
impl WireSize for msg_type {
fn wire_size(&self) -> usize {
4
}
}
impl WireSize for reject_stat {
fn wire_size(&self) -> usize {
4
}
}
impl WireSize for rejected_reply {
fn wire_size(&self) -> usize {
4 + match self {
Self::RPC_MISMATCH(inner) => inner.wire_size(),
Self::AUTH_ERROR(inner) => inner.wire_size(),
}
}
}
impl WireSize for reply_body<Bytes> {
fn wire_size(&self) -> usize {
4 + match self {
Self::MSG_ACCEPTED(inner) => inner.wire_size(),
Self::MSG_DENIED(inner) => inner.wire_size(),
}
}
}
impl WireSize for reply_data<Bytes> {
fn wire_size(&self) -> usize {
4 + match self {
Self::SUCCESS(inner) => inner.wire_size(),
Self::PROG_MISMATCH(inner) => inner.wire_size(),
Self::default => 0,
}
}
}
impl WireSize for reply_stat {
fn wire_size(&self) -> usize {
4
}
}
impl WireSize for results<Bytes> {
fn wire_size(&self) -> usize {
self.0.wire_size()
+ pad_length(self.0.wire_size()) + 4
}
}
impl WireSize for rpc_msg<Bytes> {
fn wire_size(&self) -> usize {
self.xid.wire_size() +
self.body.wire_size() +
0
}
}
}

