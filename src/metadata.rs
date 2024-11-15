use crate::{Encryption, File, Metadata};
use acr::{
    encryption::aes256cbc,
    hash::{murmur3, sha256},
};
use dh::{recommended::*, Readable};
use std::io::Result;

pub fn verify_integrity<'a>(reader: &'a mut dyn Readable<'a>, meta: &Metadata) -> Result<bool> {
    let hash = meta.checksum;
    let offset = if meta.version > 2 { 128 } else { 64 };
    let size = reader.size()?;

    let calculated = murmur3(reader, offset, size - offset, 0x31082007)?;
    Ok(calculated == hash)
}

pub fn metadata<'a>(reader: &'a mut dyn Readable<'a>, password: Option<&str>) -> Result<Metadata> {
    let mut version = if reader.read_bytes(4)? == b"SFA\0" {
        1
    } else {
        2
    };
    let checksum = reader.read_u32le()?;
    let file_count = reader.read_u32le()?;
    let pwd_hash: [u8; 32] = reader.read_bytes(32)?.try_into().unwrap();
    let iv: [u8; 16] = reader.read_bytes(16)?.try_into().unwrap();
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

    let encrypted = !(pwd_hash == [0; 32] && iv == [0; 16]);

    let mut decrypted_reader = None;
    let body: &mut dyn Readable = if encrypted {
        if password.is_none() {
            return Ok(Metadata {
                version,
                checksum,
                encryption: Some(Encryption {
                    hash: [0; 32],
                    hash_expected: pwd_hash,
                    iv,
                    decrypted: vec![],
                }),
                files: vec![],
                main_file: None,
            });
        }

        let password = password.unwrap();

        let key = sha256(
            &mut dh::data::read_ref(password.as_bytes()),
            0,
            password.len() as u64,
        )?;

        let hash = sha256(&mut dh::data::read_ref(&key), 0, 32)?;

        if hash != pwd_hash {
            return Ok(Metadata {
                version,
                checksum,
                encryption: Some(Encryption {
                    hash,
                    hash_expected: pwd_hash,
                    iv,
                    decrypted: vec![],
                }),
                files: vec![],
                main_file: None,
            });
        }

        let pos = reader.pos()?;
        let size = reader.size()? - pos;
        let decrypted = aes256cbc::decrypt(reader, &key, &iv, pos, size)?;
        decrypted_reader = Some(dh::data::read(decrypted));
        decrypted_reader.as_mut().unwrap()
    } else {
        reader
    };

    let mut files = Vec::new();

    for _ in 0..file_count {
        let size = body.read_u64le()?;
        let path_length = body.read_u16le()?;
        let path = body.read_utf8(path_length as u64)?;
        let directory = path.starts_with("//");
        let offset = body.pos()?;
        body.jump(size as i64 + path_length as i64)?;
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
                hash: pwd_hash,
                hash_expected: pwd_hash,
                iv,
                decrypted: dh::data::close(decrypted_reader.unwrap()),
            })
        } else {
            None
        },
        files,
        main_file: if main > 0 { Some(main - 1) } else { None },
    })
}
