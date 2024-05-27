use bincode::{ Decode, Encode};
use bincode::config::{Configuration,Fixint, BigEndian, Limit};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use bytes::{Buf, BytesMut};

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum MsgKind{
    ///Last fragment of a packet and/or whole packet. 
    LastFragment(u16), 
    /// Fragment of a packet at seq with offset given
    Fragment {seq:u64, len:u16}, 
    /// Message with explicitly no data in it, the body will be set to the complete nonce of the sender
    Keepalive,
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct OuterHeader{
    /// Rolling counter of sent packets, when this wraps the world explodes
    pub seq: u64,     
    /// A signature that allows the crypto engine to reject obviously invalid packets
    pub signature:u8, 
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct InnerHeader{    
    /// Message type selector       
    pub msgkind: MsgKind,
}


pub struct UntrustedMessage{
    pub header: OuterHeader,
    pub body: BytesMut
}
impl UntrustedMessage{
    
    /// Parse a raw untrusted UDP frame so it can be passed off to decryptor thread.
    /// At this point we have no idea if the frame is valid or not, obviously.
    pub fn from_buffer(mut buf:bytes::BytesMut)->Result<UntrustedMessage>{        
            let config = BinCodeConfig::default();
            
            let (header, len): (OuterHeader, usize) = bincode::decode_from_slice(&buf, config)?;
            let body = buf.split_off(len);
            Ok(UntrustedMessage{header, body})
    }    
}

pub struct TrustedMessage{
    pub outer_header: OuterHeader,
    pub inner_header: InnerHeader,
    pub body: BytesMut
}

impl TrustedMessage{
    pub fn from_decrypted_msg(mut msg: UntrustedMessage)->Result<Self>{
        let config = BinCodeConfig::default();
        
        let (header, len): (InnerHeader, usize) = bincode::decode_from_slice(&msg.body, config)?;
        todo!()
    }
}


type BinCodeConfig = Configuration<BigEndian, Fixint, Limit<128>>;





/// Reconstructs the frames sent from the peer. Keeps track of sequence numbers and fragmentation.
pub struct Reassembler<const N:usize>{
    pipeline:[u8;N],
    seq:u64,
    
}


impl <const N:usize> Reassembler<N>{

    
    
    
}

 



// pub async fn parse_udp_frame(mut buf:bytes::Bytes)->Result<Message>{
//     let config = BinCodeConfig::default();
    
//     let (header, len): (Header, usize) = bincode::decode_from_slice(&buf, config)?;
//     let body = buf.split_off(len);
//     Ok(Message{header, body})
// }