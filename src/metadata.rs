use crate::{Encryption, File, Metadata};
use dh::{recommended::*, Readable};
use std::io::Result;

pub fn metadata(reader: &mut dyn Readable, password: Option<String>) -> Result<Metadata> {
    let mut version = if reader.read_bytes(4)? == b"SFA\0" {
        1
    } else {
        2
    };
    let checksum = reader.read_u32le()?;
    let file_count = reader.read_u32le()?;
    let pwd_hash = reader.read_bytes(32)?;
    let iv = reader.read_u128le()?;
    let main = reader.read_u32le()?;

    if version == 2 {
        let pos_before = reader.pos()?;
        let p1 = reader.read_u128le();
        if let Ok(p1) = p1 {
            if p1 == 0 {
                let p2 = reader.read_u128le();
                if let Ok(p2) = p2 {
                    if p2 == 0 {
                        version = 3;
                    } else {
                        reader.to(pos_before)?;
                    }
                } else {
                    reader.to(pos_before)?;
                }
            } else {
                reader.to(pos_before)?;
            }
        } else {
            reader.to(pos_before)?;
        }
    }

    let encrypted = !(pwd_hash == [0; 32] && iv == 0);

    // TODO: Encryption

    let mut files = Vec::new();

    for _ in 0..file_count {
        let size = reader.read_u64le()?;
        let path_length = reader.read_u16le()?;
        let path = reader.read_utf8(path_length as u64)?;
        let directory = path.starts_with("//");
        let offset = reader.pos()?;
        reader.jump(size as i64 + path_length as i64)?;
        files.push(File {
            path: if directory {
                path.strip_prefix("//").unwrap().to_string()
            } else {
                path
            },
            directory,
            offset,
            length: size,
        });
    }

    Ok(Metadata {
        version,
        checksum,
        encryption: if encrypted {
            Some(Encryption {
                hash: [0; 32],
                hash_expected: pwd_hash.try_into().unwrap(),
                iv,
                decrypted: Vec::new(),
            })
        } else {
            None
        },
        files,
        main_file: if main > 0 { Some(main - 1) } else { None },
    })
}
