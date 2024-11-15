use crate::FileWithSource;
use acr::{
    encryption::sha256cbc,
    hash::{murmur3, sha256},
};
use dh::{recommended::*, Readable, Rw, Writable};
use std::io::Result;

pub fn create<'a>(
    version: u8,
    sources: Vec<FileWithSource<'a>>,
    encryption: Option<(&str, &[u8; 16])>,
    main_file: Option<u32>,
    target: &'a mut dyn Rw<'a>,
    buffer_size: u64,
) -> Result<(u64, u32)> {
    let encrypted = encryption.is_some();
    let key = if encrypted {
        sha256(
            &mut dh::data::read_ref(encryption.unwrap().0.as_bytes()),
            0,
            encryption.unwrap().0.len() as u64,
        )?
    } else {
        [0; 32]
    };
    let key_hash = if encrypted {
        sha256(&mut dh::data::read_ref(&key), 0, 32)?
    } else {
        [0; 32]
    };
    let iv = if encrypted {
        encryption.unwrap().1
    } else {
        &[0; 16]
    };

    target.write_bytes(if version == 1 { b"SFA\0" } else { b"HSSP" })?;
    let hash_pos = target.pos()?;
    target.write_u32le(0)?;
    target.write_u32le(sources.len() as u32)?;
    if encrypted {
        target.write_bytes(&key_hash)?;
        target.write_bytes(iv)?;
    } else {
        target.write_bytes(&[0; 48])?;
    }
    if main_file.is_some() {
        let main_file = main_file.unwrap();
        target.write_u32le(if main_file == (main_file % 4294967295) {
            main_file + 1
        } else {
            0
        })?;
    } else {
        target.write_u32le(0)?;
    }

    if version > 2 {
        target.write_bytes(&[0; 64])?;
    }

    let body_pos = target.pos()?;

    if encrypted {
        let mut body = dh::data::rw_empty();
        for source in sources {
            let file = source.0;
            let reader = source.1;
            let path = if file.directory {
                &(("//").to_string() + &file.path)
            } else {
                &file.path
            };

            body.write_u64le(file.length)?;
            body.write_u16le(path.len() as u16)?;
            body.write_utf8(path)?;
            reader.copy_at(file.offset, file.length, &mut body, buffer_size)?;
            body.write_bytes(&vec![0; path.len()])?;
        }

        let body_size = body.size()?;

        let cipher = sha256cbc::encrypt(&mut body, &key, iv, 0, body_size)?;
        target.write_bytes(&cipher)?;
    } else {
        for source in sources {
            let file = source.0;
            let reader = source.1;
            let path = if file.directory {
                &(("//").to_string() + &file.path)
            } else {
                &file.path
            };

            target.write_u64le(file.length)?;
            target.write_u16le(path.len() as u16)?;
            target.write_utf8(path)?;
            reader.copy_at(
                file.offset,
                file.length,
                Writable::as_trait(target),
                buffer_size,
            )?;
            target.write_bytes(&vec![0; path.len()])?;
        }
    }

    let body_size = target.pos()? - body_pos;

    let hash = murmur3(Readable::as_trait(target), body_pos, body_size)?;

    Ok((hash_pos, hash))
}

// TODO: Implement this inside the create function
pub fn write_hash(target: &mut dyn Writable, create_result: (u64, u32)) -> Result<()> {
    target.write_u32le_at(create_result.0, create_result.1)
}
