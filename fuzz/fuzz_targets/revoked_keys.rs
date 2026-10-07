//! revoked_keys files: key lists and binary KRLs.
#![no_main]

use libfuzzer_sys::fuzz_target;

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fuzz_target!(|data: &[u8]| {
    if let Ok(list) = qsh::server::revoked::Revoked::parse(data) {
        let blob = ssh_key::PublicKey::from_openssh(KEY).unwrap().to_bytes().unwrap();
        let _ = list.revoked(&qsh::authkeys::Offered::from_bytes(&blob).unwrap());
    }
    let _ = qsh::authkeys::Offered::from_bytes(data);
});
