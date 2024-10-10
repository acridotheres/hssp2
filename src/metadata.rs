use crate::Metadata;
use dh::{recommended::*, Readable};
use std::io::Result;

pub fn metadata<'a>(reader: &mut dyn Readable) -> Result<Metadata> {
    todo!()
}
