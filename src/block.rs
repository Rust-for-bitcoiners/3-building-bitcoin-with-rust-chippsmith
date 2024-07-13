#![allow(unused)]
use secp256k1::{Secp256k1, SecretKey};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::LinkedList as List;
use std::io::{Read, Write};

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Keypair, Parity, Verification, XOnlyPublicKey};

#[cfg(feature = "rand-std")]
pub use secp256k1::rand;

static BLOCK_MAGIC: u32 = 0xd9b4bef9;

struct BlockChain {
    blocks: List<Block>,
}

impl BlockChain {
    fn block_height(self) -> usize {
        self.blocks.len()
    }
}

#[derive(Debug)]

pub enum Error {
    Io(std::io::Error),
    ParseFailed(&'static str),
    UnsupportedSegwitFlag(u8),
}
#[derive(Debug, Serialize)]

pub struct Amount(u64);

#[derive(Debug, Serialize)]

struct Block {
    magic: u32,
    block_size: u32,
    block_header: BlockHeader,
    transaction_count: u32, // u32 instead of var_int for simplicity
    transactions: List<Transaction>,
}

impl Block {
    pub fn transaction_count(self) -> u32 {
        println!("{}", self.transaction_count);
        self.transaction_count
    }

    pub fn version(self) -> u32 {
        self.block_header.version
    }
}

#[derive(Debug, Serialize)]

// need to implemnet encode and decode for block header and block
struct BlockHeader {
    version: u32,
    hashprev_block: u128, //Using u128 for hash_prev_block and hash_merkle_root for simplicity
    hash_merkle_root: u128,
    time: u32,
    bits: u32,
    nonce: u32,
}

#[derive(Debug)]

struct Transaction {
    version: Version,
    inputs: List<TxIn>,
    outputs: List<TxOut>,
    lock_time: u32,
}

impl Transaction {
    pub fn txid(&self) -> Txid {
        let mut txid_data = Vec::new();
        self.version.consensus_encode(&mut txid_data).unwrap();
        //self.inputs.consensus_encode(&mut txid_data).unwrap(); //Need to implement encodeable trait for Linked_List or change to Vec
        //self.outputs.consensus_encode(&mut txid_data).unwrap();
        self.lock_time.consensus_encode(&mut txid_data).unwrap();
        Txid::new(txid_data)
    }
}

#[derive(Debug, Serialize)]
pub struct Txid([u8; 32]);

impl Txid {
    pub fn from_bytes(bytes: [u8; 32]) -> Txid {
        Txid(bytes)
    }
}

impl Txid {
    fn new(data: Vec<u8>) -> Txid {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash1 = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hash1);
        let hash2 = hasher.finalize();

        Txid(hash2.into())
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tx = serializer.serialize_struct("Transaction", 5)?;
        tx.serialize_field("transaction id", &self.txid())?;
        tx.serialize_field("version", &self.version)?;
        tx.serialize_field("inputs", &self.inputs)?;
        tx.serialize_field("outputs", &self.outputs)?;
        tx.serialize_field("locktime", &self.lock_time)?;
        tx.end()
    }
}

#[derive(Debug, Serialize)]
pub struct Witness {
    content: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize)]
pub struct TxIn {
    pub previous_txid: Txid,
    pub previous_vout: u32,
    pub script_sig: String,
    pub sequence: u32,
    pub witness: Witness,
}

#[derive(Debug, Serialize)]
struct TxOut {
    amount: Amount,
    script_pub_key: String,
    // 1 btc = 10^8 satoshis, in total 10^8 * 21 * 10^6 = 2.1 * 10^15
    // maximum value of u64 is greater than 10^19
    // so u64 is enough to store all valid satoshis
}
#[derive(Debug, Serialize)]
pub struct Version(pub u32);

#[derive(Debug, Serialize)]
pub struct CompactSize(pub u64);

pub trait Decodable: Sized {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error>;
}

impl Decodable for u8 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 1];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u8::from_le_bytes(buffer))
    }
}

impl Decodable for u16 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 2];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u16::from_le_bytes(buffer))
    }
}

impl Decodable for u32 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u32::from_le_bytes(buffer))
    }
}
impl Decodable for u64 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

impl Decodable for String {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let length = CompactSize::consensus_decode(reader)?.0;
        let mut buffer = vec![0_u8; length as usize];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(hex::encode(buffer))
    }
}

impl Decodable for Version {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Version(u32::consensus_decode(reader)?))
    }
}

impl Decodable for CompactSize {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        let n = u8::consensus_decode(r)?;
        match n {
            0xFF => {
                let x = u64::consensus_decode(r)?;
                Ok(CompactSize(x))
            }
            0xFE => {
                let x = u32::consensus_decode(r)?;
                Ok(CompactSize(x as u64))
            }
            0xFD => {
                let x = u16::consensus_decode(r)?;
                Ok(CompactSize(x as u64))
            }
            n => Ok(CompactSize(n as u64)),
        }
    }
}

pub trait Encodable {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error>;
}

impl Encodable for u8 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let b = self.to_le_bytes();
        let len = writer.write(b.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u16 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let b = self.to_le_bytes();
        let len = writer.write(b.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u32 {
    fn consensus_encode<W: Write>(&self, w: &mut W) -> Result<usize, Error> {
        let b = self.to_le_bytes();
        let len = w.write(b.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u64 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let b = self.to_le_bytes();
        let len = writer.write(b.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for Version {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = self.0.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for String {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let b = hex::decode(self).expect("should be valid hex string");
        let compact_size_length = CompactSize(b.len() as u64).consensus_encode(writer)?;
        let str_len = writer.write(&b).map_err(Error::Io)?;
        Ok(compact_size_length + str_len)
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = self.0.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for TxOut {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.amount.consensus_encode(writer)?;
        len += self.script_pub_key.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.previous_txid.consensus_encode(writer)?;
        len += self.previous_vout.consensus_encode(writer)?;
        len += self.script_sig.consensus_encode(writer)?;
        len += self.sequence.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for Txid {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = self.0.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for [u8; 32] {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = writer.write(self).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for CompactSize {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        match self.0 {
            0..=0xfc => (self.0 as u8).consensus_encode(writer),
            0xfd..=0xffff => {
                writer.write([0xFD].as_slice()).map_err(Error::Io)?;
                (self.0 as u16).consensus_encode(writer)?;
                Ok(3)
            }
            0x10000..=0xffffffff => {
                writer.write([0xFE].as_slice()).map_err(Error::Io)?;
                (self.0 as u32).consensus_encode(writer)?;
                Ok(5)
            }

            _ => {
                writer.write([0xff].as_slice()).map_err(Error::Io)?;
                (self.0 as u64).consensus_encode(writer)?;
                Ok(9)
            }
        }
    }
}

// write encodable for List<TxIn> and List<TxOut>

//TODO figure out these two...
impl Encodable for Vec<TxIn> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut length = CompactSize(self.len() as u64).consensus_encode(writer)?;
        for input in self.iter() {
            length += input.consensus_encode(writer)?;
        }
        Ok(length)
    }
}

impl Encodable for Vec<TxOut> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut length = CompactSize(self.len() as u64).consensus_encode(writer)?;
        for out in self.iter() {
            length += out.consensus_encode(writer)?;
        }
        Ok(length)
    }
}

struct Script([u8]);

#[derive(Debug)]
struct ScriptBuf(Vec<u8>);

impl ScriptBuf {
    const fn new() -> Self {
        ScriptBuf(Vec::new())
    }

    fn new_p2pk(&self, pubkey: &PublicKey) -> Self {
        let OP_CHECKSIG = Opcode { code: 0xac };
        Builder::new()
            .push_key(pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network kind on which this key should be used
    //pub network: NetworkKind,
    /// The actual ECDSA key
    pub inner: secp256k1::SecretKey,
}

impl PrivateKey {
    pub fn new(key: secp256k1::SecretKey) -> PrivateKey {
        PrivateKey {
            compressed: true,
            inner: key,
        }
    }

    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: secp256k1::PublicKey::from_secret_key(secp, &self.inner),
        }
    }
}

pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: secp256k1::PublicKey,
}

impl PublicKey {
    pub fn from_private_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &PrivateKey,
    ) -> PublicKey {
        sk.public_key(secp)
    }
}

pub struct Opcode {
    code: u8,
}

struct Builder(ScriptBuf, Option<Opcode>);

impl Builder {
    pub const fn new() -> Self {
        Builder(ScriptBuf::new(), None)
    }
    pub fn push_key(self, key: &PublicKey) -> Builder {
        if key.compressed {
            //self.push_slice(key.inner.serialize())
            //self.0 = key.inner.serialize();  // need to figure out how to push public key into scriptbuf without checking for it being checked for correctness...
            self
        } else {
            self.push_slice(key.inner.serialize_uncompressed())
        }
    }

    pub fn push_slice<T>(mut self, data: T) -> Builder {
        self.0 = ScriptBuf::new(); // hacky... shouldnt be empty script, should be data
                                   //self.0.push_slice(data);  //cant implement push slice because dont know how to restrict to pushbytes type
        self.1 = None;
        self
    }

    pub fn push_opcode(mut self, data: Opcode) -> Builder {
        self.0 = ScriptBuf::new(); //hacky not sure how else to no resturct to pushbytes type
        self.1 = Some(data);
        self
    }

    pub fn into_script(self) -> ScriptBuf {
        self.0
    }
}

// Try to include bitcoin related functionalities like serialization, computing addresses etc.,
// You can add your own methods for different types and associated unit tests

#[cfg(test)]
mod tests {
    use secp256k1::SecretKey;

    use super::*;

    fn create_tx_in(
        previous_txid: Txid,
        previous_vout: u32,
        script_sig: String,
        sequence: u32,
        witness: Witness,
    ) -> TxIn {
        TxIn {
            previous_txid,
            previous_vout,
            script_sig,
            sequence,
            witness,
        }
    }

    fn create_tx_out(amount: Amount, script_pub_key: String) -> TxOut {
        TxOut {
            amount,
            script_pub_key,
        }
    }

    fn create_transaction() -> Transaction {
        let mut v = Vec::new();
        v.push(8);
        let mut w = Vec::new();
        w.push(v);
        let witness = Witness { content: w };
        let tx_in = create_tx_in(
            Txid([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            0,
            String::from("Signature"),
            0xffffffff,
            witness,
        );
        let tx_out = create_tx_out(Amount(6500), String::from("lockingscript"));

        let mut inputs = List::new();
        let mut outputs = List::new();

        inputs.push_back(tx_in);
        outputs.push_back(tx_out);

        Transaction {
            version: Version(0),
            inputs: inputs,
            outputs: outputs,
            lock_time: 0,
        }
    }

    fn create_block_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            hashprev_block: 00004344,
            hash_merkle_root: 123456,
            time: 454,
            bits: 1,
            nonce: 1700,
        }
    }

    fn create_block() -> Block {
        let mut transactions = List::new();
        transactions.push_back(create_transaction());
        let block_header = create_block_header();
        Block {
            magic: BLOCK_MAGIC,
            block_header,
            block_size: 400,
            transaction_count: 1,
            transactions,
        }
    }

    fn create_blockchain() -> BlockChain {
        let block = create_block();
        let mut blocks = List::new();
        blocks.push_back(block);
        BlockChain { blocks }
    }

    #[test]
    fn test_tx_count() {
        let block = create_block();
        assert_eq!(block.transaction_count(), 1)
    }

    #[test]
    fn test_block_version() {
        let block = create_block();
        assert_eq!(block.version(), 1)
    }

    #[test]
    fn test_block_height() {
        let block_chain = create_blockchain();
        assert_eq!(block_chain.block_height(), 1)
    }

    #[test]
    fn test_encode_u8() {
        let mut v = Vec::new();
        let x = 25_u8;
        let length = x.consensus_encode(&mut v).unwrap();
        assert_eq!(length, 1);
        assert_eq!(v, [25])
    }

    #[test]
    fn test_encode_u16() {
        let mut v = Vec::new();
        let x = 25_u16;
        let length = x.consensus_encode(&mut v).unwrap();
        assert_eq!(length, 2);

        assert_eq!(v, [25, 0])
    }

    #[test]
    fn test_encode_u32() {
        let mut v = Vec::new();
        let x = 25_u32;
        let length = x.consensus_encode(&mut v).unwrap();
        assert_eq!(length, 4);

        assert_eq!(v, [25, 0, 0, 0])
    }

    #[test]
    fn test_encode_u64() {
        let mut v = Vec::new();
        let x = 25_u64;
        let length = x.consensus_encode(&mut v).unwrap();
        assert_eq!(length, 8);

        assert_eq!(v, [25, 0, 0, 0, 0, 0, 0, 0])
    }

    #[test]

    fn test_encode_version() {
        let mut v = Vec::new();
        let version = Version(1);
        let length = version.consensus_encode(&mut v).unwrap();
        println!("{:?}", v);
        assert_eq!(length, 4);
        assert_eq!(v, [1, 0, 0, 0])
    }

    #[test]
    fn test_encode_string() {
        let mut v = Vec::new();
        let s = String::from("00000000");
        let length = s.consensus_encode(&mut v).unwrap();
        assert_eq!(v, [4, 0, 0, 0, 0])
    }

    #[test]
    fn test_decode_u8() {
        let mut v: &[u8] = &[8, 1];
        let a = u8::consensus_decode(&mut v).unwrap();
        assert_eq!(a, 8);
        assert_eq!(v, &[1]);
    }

    #[test]
    fn test_decode_u16() {
        let mut v: &[u8] = &[8, 1, 5];
        let a = u16::consensus_decode(&mut v).unwrap();
        assert_eq!(a, 264);
        assert_eq!(v, &[5]);
    }

    #[test]
    fn test_decode_u32() {
        let mut v: &[u8] = &[43, 0, 0, 0, 56];
        let a = u32::consensus_decode(&mut v).unwrap();
        assert_eq!(a, 43);
        assert_eq!(v, &[56]);
    }

    #[test]
    fn test_decode_u64() {
        let mut v: &[u8] = &[43, 0, 0, 0, 0, 0, 0, 0, 56];
        let a = u64::consensus_decode(&mut v).unwrap();
        assert_eq!(a, 43);
        assert_eq!(v, &[56]);
    }

    #[test]
    fn test_decode_version() {
        let mut v: &[u8] = &[1, 0, 0, 0, 56];
        let version = Version::consensus_decode(&mut v).unwrap();
        assert_eq!(1, version.0);
        assert_eq!(v, &[56]);
    }

    #[test]
    fn test_generate_address_from_private_key() {
        let secp = Secp256k1::new();
        let data: &[u8] = &[
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ];
        let secret_key = SecretKey::from_slice(data).unwrap();
        let pk = PrivateKey::new(secret_key);
        let pubkey = PublicKey::from_private_key(&secp, &pk);

        let script = ScriptBuf::new();
        let p2pk_script = script.new_p2pk(&pubkey);

        println!("{:?}", p2pk_script) //need to fix this
    }
}
