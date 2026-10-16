// rs-l1-ffi
//
// Wrap bpf_probe_read_user safely. The raw helper returns a negative errno and
// leaves the buffer untouched on failure — your API must not hand a half-filled
// buffer to the caller, and it must never panic on a short read.
//
// Implement read_user, add a #[cfg(test)] module, then:
//     labcheck --task rs-l1-ffi      (runs cargo build and cargo test)

pub fn read_user(user_addr: u64, out: &mut [u8]) -> Result<usize, i64> {
    let _ = user_addr;
    let _ = out;
    todo!()
}
