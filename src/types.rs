#[derive(Debug)]
pub struct Metadata {
    pub version: u8,
    pub checksum: u32,
    pub encryption: Option<Encryption>,
    pub files: Vec<File>,
    pub main_file: Option<u32>,
}

#[derive(Debug)]
pub struct Encryption {
    pub hash: [u8; 32],
    pub hash_expected: [u8; 32],
    pub iv: [u8; 16],
    pub decrypted: Vec<u8>,
}

#[derive(Debug)]
pub struct File {
    pub path: String,
    pub directory: bool,
    pub offset: u64,
    pub length: u64,
}
