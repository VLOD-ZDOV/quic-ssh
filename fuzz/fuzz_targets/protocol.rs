//! Every protocol message type decoded from arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use qsh::proto::{Auth, ClientMsg, Hello, Opened, Reply, Request, ServerMsg};

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<Hello>(data);
    let _ = postcard::from_bytes::<Request>(data);
    let _ = postcard::from_bytes::<Reply>(data);
    let _ = postcard::from_bytes::<Auth>(data);
    let _ = postcard::from_bytes::<ClientMsg>(data);
    let _ = postcard::from_bytes::<ServerMsg>(data);
    let _ = postcard::from_bytes::<Opened>(data);
});
