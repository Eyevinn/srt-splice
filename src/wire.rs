//! The bits of the SRT wire format the relay needs: the 16-byte packet
//! header, the handshake CIF and its extension blocks. No ARQ, no crypto.
//!
//! Reference: draft-sharabayko-srt and libsrt `srtcore/handshake.{h,cpp}`.

pub const HDR: usize = 16;
pub const HS_CIF: usize = 48;

pub const CTRL_HANDSHAKE: u16 = 0x0000;
pub const CTRL_SHUTDOWN: u16 = 0x0005;
pub const CTRL_EXT: u16 = 0x7FFF;

pub const HS_INDUCTION: u32 = 1;
pub const HS_CONCLUSION: u32 = 0xFFFF_FFFF;
/// Rejection: handshake type = 1000 + reason.
pub const HS_REJECT_BASE: u32 = 1000;

pub const SRT_MAGIC: u16 = 0x4A17;
pub const EXT_HSREQ: u16 = 1 << 0;
pub const EXT_KMREQ: u16 = 1 << 1;

pub const CMD_HSREQ: u16 = 1;
pub const CMD_HSRSP: u16 = 2;
pub const CMD_KMREQ: u16 = 3;
pub const CMD_KMRSP: u16 = 4;
pub const CMD_SID: u16 = 5;
pub const CMD_FILTER: u16 = 7;
pub const CMD_GROUP: u16 = 8;

// SRT_REJ_* (srt.h)
pub const REJ_PEER: u32 = 2;
pub const REJ_ROGUE: u32 = 4;
pub const REJ_BADSECRET: u32 = 10;
pub const REJ_UNSECURE: u32 = 11;
pub const REJ_FILTER: u32 = 14;
pub const REJ_GROUP: u32 = 15;
pub const REJ_CRYPTO: u32 = 17;
// SRT_REJX_* (access control, 1000 + HTTP-like code)
pub const REJX_BAD_REQUEST: u32 = 1400;
pub const REJX_BAD_MODE: u32 = 1405;
pub const REJX_UNACCEPTABLE: u32 = 1406;
pub const REJX_CONFLICT: u32 = 1409;

// KM message (haicrypt/hcrypt_msg.h): byte offsets.
const KM_OFS_CIPHER: usize = 8;
const KM_OFS_KLEN: usize = 15;

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

pub fn is_control(p: &[u8]) -> bool {
    p.len() >= HDR && p[0] & 0x80 != 0
}

pub fn ctrl_type(p: &[u8]) -> u16 {
    (u16::from_be_bytes([p[0], p[1]])) & 0x7FFF
}

pub fn ctrl_subtype(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[2], p[3]])
}

pub fn timestamp(p: &[u8]) -> u32 {
    be32(p, 8)
}

/// Data packet: 31-bit sequence number.
pub fn data_seq(p: &[u8]) -> u32 {
    be32(p, 0) & 0x7FFF_FFFF
}

/// Data packet: the R (retransmitted) flag of the message word.
pub fn data_rexmit(p: &[u8]) -> bool {
    be32(p, 4) & (1 << 26) != 0
}

/// Data packet: KK, the key slot the payload is encrypted with (0 = clear).
pub fn data_kk(p: &[u8]) -> u32 {
    (be32(p, 4) >> 27) & 0b11
}

#[derive(Clone, Debug)]
pub struct Ext {
    pub cmd: u16,
    /// Contents exactly as on the wire (big-endian 32-bit words).
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Handshake {
    pub version: u32,
    pub enc_field: u16,
    pub ext_field: u16,
    pub isn: u32,
    pub mss: u32,
    pub flow: u32,
    pub hs_type: u32,
    pub socket_id: u32,
    pub cookie: u32,
    pub peer_ip: [u8; 16],
    pub exts: Vec<Ext>,
}

impl Handshake {
    pub fn parse(p: &[u8]) -> Option<Handshake> {
        if p.len() < HDR + HS_CIF {
            return None;
        }
        let c = &p[HDR..];
        let mut hs = Handshake {
            version: be32(c, 0),
            enc_field: u16::from_be_bytes([c[4], c[5]]),
            ext_field: u16::from_be_bytes([c[6], c[7]]),
            isn: be32(c, 8),
            mss: be32(c, 12),
            flow: be32(c, 16),
            hs_type: be32(c, 20),
            socket_id: be32(c, 24),
            cookie: be32(c, 28),
            peer_ip: c[32..48].try_into().unwrap(),
            exts: Vec::new(),
        };
        let mut off = HS_CIF;
        while off + 4 <= c.len() {
            let cmd = u16::from_be_bytes([c[off], c[off + 1]]);
            let words = u16::from_be_bytes([c[off + 2], c[off + 3]]) as usize;
            let end = off + 4 + words * 4;
            if end > c.len() {
                return None;
            }
            hs.exts.push(Ext {
                cmd,
                data: c[off + 4..end].to_vec(),
            });
            off = end;
        }
        Some(hs)
    }

    pub fn ext(&self, cmd: u16) -> Option<&Ext> {
        self.exts.iter().find(|e| e.cmd == cmd)
    }

    /// HSREQ: (SRT version, SRT flags, latency word).
    pub fn hsreq(&self) -> Option<(u32, u32, u32)> {
        let e = self.ext(CMD_HSREQ)?;
        (e.data.len() >= 12).then(|| (be32(&e.data, 0), be32(&e.data, 4), be32(&e.data, 8)))
    }

    pub fn km(&self) -> Option<&[u8]> {
        self.ext(CMD_KMREQ).map(|e| e.data.as_slice())
    }

    /// The stream id. libsrt packs the string into 32-bit words in host
    /// order and swaps them to network order, so each 4-byte group arrives
    /// reversed (on little-endian senders, i.e. everyone).
    pub fn streamid(&self) -> Option<String> {
        let e = self.ext(CMD_SID)?;
        let mut s = Vec::with_capacity(e.data.len());
        for w in e.data.chunks(4) {
            s.extend(w.iter().rev());
        }
        while s.last() == Some(&0) {
            s.pop();
        }
        Some(String::from_utf8_lossy(&s).into_owned())
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.version.to_be_bytes());
        out.extend(self.enc_field.to_be_bytes());
        out.extend(self.ext_field.to_be_bytes());
        out.extend(self.isn.to_be_bytes());
        out.extend(self.mss.to_be_bytes());
        out.extend(self.flow.to_be_bytes());
        out.extend(self.hs_type.to_be_bytes());
        out.extend(self.socket_id.to_be_bytes());
        out.extend(self.cookie.to_be_bytes());
        out.extend(self.peer_ip);
        for e in &self.exts {
            out.extend(e.cmd.to_be_bytes());
            out.extend(((e.data.len() / 4) as u16).to_be_bytes());
            out.extend(&e.data);
        }
    }
}

/// A control packet: header + body.
pub fn control(ty: u16, subtype: u16, info: u32, ts: u32, dest: u32, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(HDR + body.len());
    p.extend((0x8000u16 | ty).to_be_bytes());
    p.extend(subtype.to_be_bytes());
    p.extend(info.to_be_bytes());
    p.extend(ts.to_be_bytes());
    p.extend(dest.to_be_bytes());
    p.extend(body);
    p
}

pub fn handshake_packet(hs: &Handshake, ts: u32, dest: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(HS_CIF + 64);
    hs.write(&mut body);
    control(CTRL_HANDSHAKE, 0, 0, ts, dest, &body)
}

/// Key material summary: (cipher, key length in bytes). Cipher 2 = AES-CTR, 4 = AES-GCM.
pub fn km_params(km: &[u8]) -> Option<(u8, u16)> {
    (km.len() > KM_OFS_KLEN).then(|| (km[KM_OFS_CIPHER], km[KM_OFS_KLEN] as u16 * 4))
}
