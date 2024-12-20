use dh::recommended::*;
use hssp2::{create, extract, metadata, verify_integrity, write_hash, File, FileWithSource};

#[test]
fn wfld_normal() {
    let mut reader = dh::file::open_r("tests/samples/wfld-normal.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2082363140);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn wfld_multiple() {
    let mut reader = dh::file::open_r("tests/samples/wfld-multiple.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 183707333);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert_eq!(meta.files[1].path, "test2.txt");
    assert!(!meta.files[1].directory);
    assert_eq!(meta.files[1].offset, 122);
    assert_eq!(meta.files[1].length, 15);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");

    let mut target = dh::data::write_new(meta.files[1].length);
    extract(&mut reader, &meta.files[1], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world! 2");
}

#[test]
fn wfld_folder() {
    let mut reader = dh::file::open_r("tests/samples/wfld-folder.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2567700355);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.files[0].path, "test");
    assert!(meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 80);
    assert_eq!(meta.files[0].length, 0);
    assert_eq!(meta.files[1].path, "test/test.txt");
    assert!(!meta.files[1].directory);
    assert_eq!(meta.files[1].offset, 109);
    assert_eq!(meta.files[1].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[1].length);
    extract(&mut reader, &meta.files[1], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn wfld_withmain() {
    let mut reader = dh::file::open_r("tests/samples/wfld-withmain.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2082363140);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert_eq!(meta.main_file, Some(0));

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn wfld_encrypted() {
    let mut reader = dh::file::open_r("tests/samples/wfld-encrypted.hssp").unwrap();

    let meta = metadata(&mut reader, None).unwrap();
    let enc = meta.encryption.unwrap();
    assert_eq!(enc.hash, [0; 32]);
    reader.rewind().unwrap();

    let meta = metadata(&mut reader, Some("password")).unwrap();
    let enc = meta.encryption.unwrap();
    assert_ne!(enc.hash, enc.hash_expected);
    reader.rewind().unwrap();

    let meta = metadata(&mut reader, Some("Password")).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 3583420655);
    assert!(meta.encryption.is_some());
    let enc = meta.encryption.unwrap();
    assert_eq!(enc.hash, enc.hash_expected);
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 18);
    assert_eq!(meta.files[0].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(
        &mut dh::data::read_ref(&enc.decrypted),
        &meta.files[0],
        &mut target,
        1024,
        0,
    )
    .unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn wfld_corrupted() {
    let mut reader = dh::file::open_r("tests/samples/wfld-corrupted.hssp").unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(!verify_integrity(&mut reader, &meta).unwrap());
}

#[test]
fn create_wfld_normal() {
    let mut target = dh::data::rw_empty();
    let mut test_txt = dh::data::read_ref(b"Hello, world!");

    let result = create(
        1,
        vec![FileWithSource(
            &File {
                path: "test.txt".to_string(),
                directory: false,
                offset: 0,
                length: 13,
            },
            &mut test_txt,
        )],
        None,
        None,
        &mut target,
        1024,
    )
    .unwrap();

    write_hash(&mut target, result).unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2082363140);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn create_wfld_multiple() {
    let mut target = dh::data::rw_empty();
    let mut test_txt = dh::data::read_ref(b"Hello, world!");
    let mut test2_txt = dh::data::read_ref(b"Hello, world! 2");

    let result = create(
        1,
        vec![
            FileWithSource(
                &File {
                    path: "test.txt".to_string(),
                    directory: false,
                    offset: 0,
                    length: 13,
                },
                &mut test_txt,
            ),
            FileWithSource(
                &File {
                    path: "test2.txt".to_string(),
                    directory: false,
                    offset: 0,
                    length: 15,
                },
                &mut test2_txt,
            ),
        ],
        None,
        None,
        &mut target,
        1024,
    )
    .unwrap();

    write_hash(&mut target, result).unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 183707333);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert_eq!(meta.files[1].path, "test2.txt");
    assert!(!meta.files[1].directory);
    assert_eq!(meta.files[1].offset, 122);
    assert_eq!(meta.files[1].length, 15);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");

    let mut target = dh::data::write_new(meta.files[1].length);
    extract(&mut reader, &meta.files[1], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world! 2");
}

#[test]
fn create_wfld_folder() {
    let mut target = dh::data::rw_empty();
    let mut test = dh::data::read(vec![]);
    let mut test_txt = dh::data::read_ref(b"Hello, world!");

    let result = create(
        1,
        vec![
            FileWithSource(
                &File {
                    path: "test".to_string(),
                    directory: true,
                    offset: 0,
                    length: 0,
                },
                &mut test,
            ),
            FileWithSource(
                &File {
                    path: "test/test.txt".to_string(),
                    directory: false,
                    offset: 0,
                    length: 13,
                },
                &mut test_txt,
            ),
        ],
        None,
        None,
        &mut target,
        1024,
    )
    .unwrap();

    write_hash(&mut target, result).unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2567700355);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.files[0].path, "test");
    assert!(meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 80);
    assert_eq!(meta.files[0].length, 0);
    assert_eq!(meta.files[1].path, "test/test.txt");
    assert!(!meta.files[1].directory);
    assert_eq!(meta.files[1].offset, 109);
    assert_eq!(meta.files[1].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[1].length);
    extract(&mut reader, &meta.files[1], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn create_wfld_withmain() {
    let mut target = dh::data::rw_empty();
    let mut test_txt = dh::data::read_ref(b"Hello, world!");

    let result = create(
        1,
        vec![FileWithSource(
            &File {
                path: "test.txt".to_string(),
                directory: false,
                offset: 0,
                length: 13,
            },
            &mut test_txt,
        )],
        None,
        Some(0),
        &mut target,
        1024,
    )
    .unwrap();

    write_hash(&mut target, result).unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 2082363140);
    assert!(meta.encryption.is_none());
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 82);
    assert_eq!(meta.files[0].length, 13);
    assert_eq!(meta.main_file, Some(0));

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(&mut reader, &meta.files[0], &mut target, 1024, 0).unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn create_wfld_encrypted() {
    let mut target = dh::data::rw_empty();
    let mut test_txt = dh::data::read_ref(b"Hello, world!");

    let result = create(
        1,
        vec![FileWithSource(
            &File {
                path: "test.txt".to_string(),
                directory: false,
                offset: 0,
                length: 13,
            },
            &mut test_txt,
        )],
        Some(("Password", &[0; 16])),
        None,
        &mut target,
        1024,
    )
    .unwrap();

    write_hash(&mut target, result).unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, Some("Password")).unwrap();

    assert!(verify_integrity(&mut reader, &meta).unwrap());
    assert_eq!(meta.version, 1);
    assert_eq!(meta.checksum, 3583420655);
    assert!(meta.encryption.is_some());
    let enc = meta.encryption.unwrap();
    assert_eq!(enc.hash, enc.hash_expected);
    assert_eq!(meta.files.len(), 1);
    assert_eq!(meta.files[0].path, "test.txt");
    assert!(!meta.files[0].directory);
    assert_eq!(meta.files[0].offset, 18);
    assert_eq!(meta.files[0].length, 13);
    assert!(meta.main_file.is_none());

    let mut target = dh::data::write_new(meta.files[0].length);
    extract(
        &mut dh::data::read_ref(&enc.decrypted),
        &meta.files[0],
        &mut target,
        1024,
        0,
    )
    .unwrap();
    assert_eq!(dh::data::close(target), b"Hello, world!");
}

#[test]
fn create_wfld_corrupted() {
    let mut target = dh::data::rw_empty();
    let mut test_txt = dh::data::read_ref(b"Hello, world!");

    create(
        1,
        vec![FileWithSource(
            &File {
                path: "test.txt".to_string(),
                directory: false,
                offset: 0,
                length: 13,
            },
            &mut test_txt,
        )],
        None,
        None,
        &mut target,
        1024,
    )
    .unwrap();

    let mut reader = target;
    reader.rewind().unwrap();
    let meta = metadata(&mut reader, None).unwrap();

    assert!(!verify_integrity(&mut reader, &meta).unwrap());
}
