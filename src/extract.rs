use crate::File;
use dh::{recommended::*, Readable, Writable};
use std::io::Result;

pub fn extract<'a>(
    source: &'a mut dyn Readable<'a>,
    file: &File,
    target: &'a mut dyn Writable<'a>,
    buffer_size: u64,
    target_pos: u64,
) -> Result<()> {
    source.copy_to_at(file.offset, target_pos, file.length, target, buffer_size)?;
    Ok(())
}
