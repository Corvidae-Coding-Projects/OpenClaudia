#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    openclaudia_fuzz::fuzz_json_tool_args(data);
});
