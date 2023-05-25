# Inspired by: <https://github.com/pseuxide/toy-arms>

# Example

```rust
use ncheat::*;

fn main() {

    unsafe {

        let process_name = "explorer.exe";

        // "explorer.exe" -> module_name: "Explorer.EXE"
        let module_name = "Explorer.EXE";

        let process_id = get_process_id_64(process_name).unwrap();

        let module_info = get_module_info_64(process_id, module_name).unwrap();

        // ** or ??
        let explorer_pat = "48 89 5C 24 08 57 ** 83 EC 30 ?? 01";

        let process_handle = get_process_handle(process_id);

        let explorer_module_data = memory_read(
            process_handle,
            module_info.modBaseAddr as isize,
            module_info.modBaseSize as usize,
        )
        .unwrap();

        let explorer_offset = pattern_find(explorer_pat, &explorer_module_data).unwrap();

        let explorer_offsets = pattern_scan(explorer_pat, &explorer_module_data).unwrap();

        println!("process_name: \"{process_name}\"");

        println!("process_id: {process_id}");

        println!("module_name: \"{module_name}\"");

        println!("module address: {:#X}", module_info.modBaseAddr as usize);

        println!("module size: {:#X}", module_info.modBaseSize,);

        println!("Explorer.EXE pat offset: {explorer_offset:#X}");

        println!("Explorer.EXE pat offsets: {explorer_offsets:#X?}");
    }

    {

        let test_data: [u8; 30] = [
            0x12, 0xAF, 0xBF, 0xC4, 0x51, 0x21, 0x98, 0x13, 0xFF, 0x20, 0x20, 0xAF, 0xBF, 0xC4,
            0x51, 0x21, 0x98, 0x13, 0xFF, 0xBA, 0x12, 0xAF, 0xBF, 0xC4, 0x51, 0x21, 0x98, 0x13,
            0xFF, 0xBA,
        ];

        // ** or ??
        let test_offset = pattern_find("51 ?? ** 13 FF ??", &test_data).unwrap();

        // ** or ??
        let test_offsets = pattern_scan("51 ** ?? 13 FF **", &test_data).unwrap();

        println!("test_offset: {:#X}", test_offset);

        println!("test_offsets: {:#X?}", test_offsets);
    }
}
```

 ```c
process_name: "explorer.exe"
process_id: 19212
module_name: "Explorer.EXE"
module address: 0x7FF779270000
module size: 0x49D000
Explorer.EXE pat offset: 0xA0420
Explorer.EXE pat offsets: [
    0xA0420,
]
test_offset: 0x4
test_offsets: [
    0x4,
    0xE,
    0x18,
]
 ```
