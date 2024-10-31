use dh::recommended::*;
use hssp2::metadata;

#[test]
fn wfld_normal() {
    let mut reader = dh::file::open_r("tests/samples/wfld-normal.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2082363140);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert!(meta.main_file.is_none());
}
