use serde::{
    de::{Error, Visitor, Unexpected},
    Deserialize, Deserializer, Serialize, Serializer
};
use serde_with::{
    serde_as, skip_serializing_none, TimestampSeconds,
};
use std::{
    fmt,
    str::FromStr,
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};

use crypto_box::{
    PublicKey, SecretKey,
    aead::Aead,
};
use generic_array::GenericArray;

pub const WG_KEY_LEN: usize = 32;
pub const PRESHARED_KEY_LEN: usize = 32;
pub const EMPTY_PRESHARED_KEY: [u8; PRESHARED_KEY_LEN] = [0u8; PRESHARED_KEY_LEN];

#[derive(Debug)]
pub enum KeyError {
    Base64DecodingError,
    SizeMismatch,
}

fn decode_key<const N: usize>(key: &str) -> Result<[u8; N], KeyError> {
    let buf = base64::decode(key)
        .map_err(|_| KeyError::Base64DecodingError)?;
    if buf.len() == N {
        Ok(buf.try_into().unwrap())
    } else {
        Err(KeyError::SizeMismatch)
    }
}

struct PublicKeyVisitor;

impl<'de> Visitor<'de> for PublicKeyVisitor {
    type Value = WireguardPublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "An Base64 encoded key")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let key = TryFrom::try_from(s)
            .map_err(|_| Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(key)
    }
}

impl<'de> Deserialize<'de> for WireguardPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PublicKeyVisitor)
    }
}

impl<'se> Serialize for WireguardPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(self.0.as_bytes()))
    }
}

#[derive(Clone)]
pub struct WireguardPublicKey(PublicKey);

impl WireguardPublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl PartialEq for WireguardPublicKey {
    fn eq(&self, other: &WireguardPublicKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl TryFrom<&str> for WireguardPublicKey {
    type Error = KeyError;
    fn try_from(key: &str) -> Result<Self, Self::Error> {
        Ok(WireguardPublicKey(crypto_box::PublicKey::from(decode_key(key)?)))
    }
}

impl From<[u8; 32]> for WireguardPublicKey {
    fn from(key: [u8; 32]) -> Self {
        WireguardPublicKey(PublicKey::from(key))
    }
}

impl TryFrom<&[u8]> for WireguardPublicKey {
    type Error = KeyError;
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        let key = <&[u8; 32]>::try_from(key).map_err(|_| KeyError::SizeMismatch)?;
        Ok(WireguardPublicKey(PublicKey::from(*key)))
    }
}

impl ToString for WireguardPublicKey {
    fn to_string(&self) -> String {
        base64::encode(&self.0)
    }
}

impl std::fmt::Debug for WireguardPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, r#"WireguardPublicKey({})"#, base64::encode(&self.0))
    }
}

impl PartialEq<[u8; WG_KEY_LEN]> for WireguardPublicKey {
    fn eq(&self, other: &[u8; WG_KEY_LEN]) -> bool {
        self.0.as_ref() == other
    }
}

impl PartialEq<WireguardPublicKey> for [u8; WG_KEY_LEN] {
    fn eq(&self, other: &WireguardPublicKey) -> bool {
        self == &other.0.as_ref()
    }
}

#[derive(Clone)]
pub struct WireguardPrivateKey(SecretKey);

#[derive(Clone)]
pub struct CypherContext {
    nonce: Vec<u8>,
    data: Vec<u8>,
    public_key: WireguardPublicKey,
}

impl WireguardPrivateKey {
    fn encrypt(&self, data: &[u8], public: &WireguardPublicKey) -> CypherContext {
        let cbox = crypto_box::Box::new(&public.0, &self.0);
        let mut rng = crypto_box::rand_core::OsRng;
        let nonce = crypto_box::generate_nonce(&mut rng);
        let encrypted = cbox.encrypt(&nonce, &data[..]).unwrap();
        CypherContext {
            nonce: nonce.as_slice().to_vec().clone(),
            data: encrypted,
            public_key: self.public_key().clone(),
        }
    }

    fn decrypt(&self, ctx: CypherContext) -> Vec<u8> {
        let cbox = crypto_box::Box::new(&ctx.public_key.0, &self.0);
        cbox.decrypt(&GenericArray::from_slice(&ctx.nonce), &ctx.data[..]).unwrap()
    }

    pub fn public_key(&self) -> WireguardPublicKey {
        WireguardPublicKey(self.0.public_key())
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl TryFrom<&str> for WireguardPrivateKey {
    type Error = KeyError;
    fn try_from(key: &str) -> Result<Self, Self::Error> {
        Ok(WireguardPrivateKey(crypto_box::SecretKey::from(decode_key(key)?)))
    }
}

impl From<[u8; 32]> for WireguardPrivateKey {
    fn from(key: [u8; 32]) -> Self {
        WireguardPrivateKey(SecretKey::from(key))
    }
}

struct PrivateKeyVisitor;

impl<'de> Visitor<'de> for PrivateKeyVisitor {
    type Value = WireguardPrivateKey;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "An Base64 encoded key")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let key = TryFrom::try_from(s)
            .map_err(|_| Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(key)
    }
}

impl<'de> Deserialize<'de> for WireguardPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PrivateKeyVisitor)
    }
}

impl<'se> Serialize for WireguardPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(self.0.as_bytes()))
    }
}


#[derive(PartialEq, Debug, Clone)]
pub struct AllowedIp {
    ipaddr: IpAddr,
    cidr_mask: u8,
}

struct AllowedIpVisitor;

impl<'de> Visitor<'de> for AllowedIpVisitor {
    type Value = AllowedIp;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a IPv4/v6 net")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        let ip: AllowedIp = TryFrom::try_from(s)
            .map_err(|_| Error::invalid_value(Unexpected::Str(s), &self))?;
        Ok(ip)
    }
}

impl<'de> Deserialize<'de> for AllowedIp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AllowedIpVisitor)
    }
}

impl Serialize for AllowedIp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<&wireguard_uapi::get::AllowedIp> for AllowedIp {
    fn from(ip: &wireguard_uapi::get::AllowedIp) -> Self {
        AllowedIp {
            ipaddr: ip.ipaddr,
            cidr_mask: ip.cidr_mask,
        }
    }
}

impl<'a> Into<wireguard_uapi::set::AllowedIp<'a>> for &'a AllowedIp {
    fn into(self) -> wireguard_uapi::set::AllowedIp<'a> {
        wireguard_uapi::set::AllowedIp {
            ipaddr: &self.ipaddr,
            cidr_mask: Some(self.cidr_mask),
        }
    }
}

impl TryFrom<&str> for AllowedIp {
    type Error = wireguard_uapi::get::ParseAllowedIpError;

    fn try_from(ip: &str) -> Result<Self, Self::Error> {
        Ok((&wireguard_uapi::get::AllowedIp::from_str(ip)?).into())
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ipaddr, self.cidr_mask)
    }
}

pub fn serialize_optional_preshared_key<S>(data: &Option<&[u8; PRESHARED_KEY_LEN]>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(data) = data {
        let b64 = base64::encode(data);
        s.serialize_some(&b64)
    } else {
        s.serialize_none()
    }
}

pub fn deserialize_optional_preshared_key<'de, D>(deserializer: D) -> Result<Option<[u8; PRESHARED_KEY_LEN]>, D::Error>
where
  D: Deserializer<'de>,
{
    let val = String::deserialize(deserializer)?;
    let key = base64::decode(val)
        .map_err(|_| D::Error::custom("Can't decode base64 value"))?;
    let key = key.as_slice().try_into()
        .map_err(|_| D::Error::invalid_length(key.len(), &"a key with 32 bytes"))?;
    Ok(Some(key))
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub public_key: WireguardPublicKey,
    #[serde(default, deserialize_with = "deserialize_optional_preshared_key")]
    pub preshared_key: Option<[u8; PRESHARED_KEY_LEN]>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub allowed_ips: Option<Vec<AllowedIp>>,
    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub last_handshake: Option<SystemTime>,
}

impl From<&wireguard_uapi::get::Peer> for PeerInfo {
    fn from(peer: &wireguard_uapi::get::Peer) -> Self {
        let preshared_key = if peer.preshared_key.iter().all(|&x| x == 0) {
            None
        } else {
            Some(peer.preshared_key)
        };

        PeerInfo {
            public_key: WireguardPublicKey::from(peer.public_key),
            preshared_key: preshared_key,
            persistent_keepalive: Some(peer.persistent_keepalive_interval),
            last_handshake: Some(SystemTime::now()),
            endpoint: peer.endpoint,
            rx_bytes: Some(peer.rx_bytes),
            tx_bytes: Some(peer.tx_bytes),
            allowed_ips: Some(peer.allowed_ips.iter().map(AllowedIp::from).collect()),
        }
    }
}

impl<'a> Into<wireguard_uapi::set::Peer<'a>> for &'a PeerInfo {
    fn into(self) -> wireguard_uapi::set::Peer<'a> {
        let mut flags = vec![];
        if self.allowed_ips.is_some() {
            flags.push(wireguard_uapi::linux::set::WgPeerF::ReplaceAllowedIps);
        }

        let preshared_key = match &self.preshared_key {
            Some(key) => {
                let key: &[u8; 32] = key.as_slice().try_into().expect("A 32 bytes preshared key");
                Some(key)
            },
            None => None,
        };

        wireguard_uapi::set::Peer {
            public_key: self.public_key.as_bytes(),
            preshared_key: preshared_key,
            endpoint: self.endpoint.as_ref(),
            persistent_keepalive_interval: self.persistent_keepalive,
            allowed_ips: self.allowed_ips
                .as_ref()
                .map(|v| {
                    v.iter()
                    .map(|ip| ip.into())
                    .collect()
                }).unwrap_or(vec![]),
            protocol_version: None,
            flags,
        }
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: Option<String>,
    pub private_key: Option<WireguardPrivateKey>,
    pub public_key: Option<WireguardPublicKey>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Option<Vec<PeerInfo>>,
}

impl Device {
    pub fn try_into_device<'a>(&'a self, iface: &'a str) -> Result<wireguard_uapi::set::Device<'a>, String> {
        let mut peers = vec![];
        if self.peers.is_some() {
            for peer in self.peers.as_ref().unwrap().iter() {
                peers.push(peer.into());
            }
        }

        Ok(wireguard_uapi::set::Device {
            interface: wireguard_uapi::DeviceInterface::from_name(iface),
            private_key: self.private_key.as_ref().map(|key| key.as_bytes()),
            flags: vec![],
            listen_port: self.listen_port,
            fwmark: self.fwmark,
            peers,
        })
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Device {{ name: {:?}, private_key: {:?}, public_key: {:?}, listen_port: {:?}, fwmark: {:?}, peers: {:?} }}",
            self.name,
            self.private_key.as_ref().map(|_| "*secret*".to_string()),
            self.public_key,
            self.listen_port,
            self.fwmark,
            self.peers)
    }
}

impl TryFrom<wireguard_uapi::get::Device> for Device {
    type Error = String;

    fn try_from(device: wireguard_uapi::get::Device) -> Result<Self, String> {
        let mut public_key = None;
        if device.public_key.is_some() {
            public_key = Some(WireguardPublicKey::try_from(device.public_key.unwrap())
                .map_err(|_| format!("Bad public key of device {}", device.ifname))?);
        }

        let mut private_key = None;
        if device.private_key.is_some() {
            private_key = Some(WireguardPrivateKey::try_from(device.private_key.unwrap())
                .map_err(|_| format!("Bad private key of device {}", device.ifname))?);
        }

        Ok(Device {
            name: Some(device.ifname.clone()),
            private_key,
            public_key,
            listen_port: Some(device.listen_port),
            fwmark: Some(device.fwmark),
            peers: Some(device.peers.iter().map(PeerInfo::from).collect()),
        })
    }
}

use rocket::http::Status;
use rocket::serde::json::Json;

pub fn status_ok<T>(data_name: &str, data: Option<T>) -> (Status, Json<serde_json::Value>)
where T: Serialize,
{
    (Status::Ok, Json(serde_json::json!({ "status": "ok", data_name: data })))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    #[test]
    fn parse_peer_info_json_minimal() {
        let json = r#"
        {
            "public_key": "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k="
        }
        "#;

        let info = serde_json::from_str::<PeerInfo>(json).unwrap();
        assert_eq!(None, info.allowed_ips);
        assert_eq!(None, info.rx_bytes);
        assert_eq!(None, info.tx_bytes);
        assert_eq!(None, info.persistent_keepalive);
        assert_eq!(PUBLIC_KEY, info.public_key.to_string());
        assert_eq!(None, info.endpoint);
        assert_eq!(None, info.last_handshake);
    }

    fn parse_peer_info_json_full() {
        let json = r#"
        {
            "public_key": "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k=",
            "preshared_key": "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k=",
            "endpoint": "127.0.0.1:1",
            "persistent_keepalive": 60,
            "rx_bytes": 1,
            "tx_bytes": 2,
            "allowed_ips": [ "127.0.0.1/32" ],
            "last_handshake", 1,
        }
        "#;

        let info = serde_json::from_str::<PeerInfo>(json).unwrap();
        assert_eq!(info.allowed_ips, Some(vec![AllowedIp::try_from("127.0.0.1/32").unwrap()]));
        assert_eq!(Some(1), info.rx_bytes);
        assert_eq!(Some(2), info.tx_bytes);
        assert_eq!(Some(60), info.persistent_keepalive);
        assert_eq!(PUBLIC_KEY, info.public_key.to_string());
        assert_eq!(Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1))), info.endpoint);
        assert_eq!(info.last_handshake,
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1)));
    }
        
    const PRIVATE_KEY: &str = "+LM/XVByQ3VN+fIFJ1R3tRQJQlpn7SLDkcJGTp6mf2w=";
    const PUBLIC_KEY: &str = "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k=";
    const PUBLIC_KEY_BYTES: [u8; 32] = [0x1d, 0x48, 0x97, 0x8a, 0x45, 0x50, 0x57, 0x6f, 0xe4, 0x75, 0x5c, 0xa0, 0x73, 0xa3, 0xfe, 0x97, 0x5f, 0x47, 0x20, 0xd4, 0x17, 0xe4, 0xce, 0x12, 0xb1, 0xfc, 0x12, 0x74, 0xb9, 0x00, 0xaf, 0x49];

    fn public_key() -> WireguardPublicKey {
        WireguardPublicKey::try_from(PUBLIC_KEY).unwrap()
    }

    fn private_key() -> WireguardPrivateKey {
        WireguardPrivateKey::try_from(PRIVATE_KEY).unwrap()
    }

    fn key_pair() -> (WireguardPrivateKey, WireguardPublicKey) {
        (private_key(), public_key())
    }

    #[test]
    fn public_key_debug() {
        let key_debug = format!("{:?}", public_key());
        assert_eq!(format!("WireguardPublicKey({})", PUBLIC_KEY), key_debug);
    }

    #[test]
    fn public_key_to_string() {
        let key_debug = public_key().to_string();
        assert!(key_debug.contains(PUBLIC_KEY));
    }

    #[test]
    fn public_key_to_json() {
        assert_eq!(format!("\"{}\"", PUBLIC_KEY), serde_json::to_string(&public_key()).unwrap());
    }

    #[test]
    fn encryption() {
        let cleartext = "hello world!";
        let key1 = private_key();
        let key2 = WireguardPrivateKey::try_from("uCpndM6PpglY176p2hCQLvoBbFryNrrqY1fxhx0AelQ=").unwrap();
        let ctx = key1.encrypt(cleartext.as_bytes(), &key2.public_key());
        let decrypted = key2.decrypt(ctx);
        let decrypted = String::from_utf8(decrypted).unwrap();
        assert_eq!(cleartext, decrypted);
    }

    #[test]
    fn parse_json_to_allowed_ipv4() {
        let text = r#""127.0.0.1/32""#;
        let ip_parsed = serde_json::from_str::<AllowedIp>(text).unwrap();
        let ip_ref = AllowedIp { ipaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), cidr_mask: 32 };
        assert_eq!(ip_ref, ip_parsed);
    }

    #[test]
    fn allowed_ipv4_to_json() {
        let ip = AllowedIp { ipaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), cidr_mask: 32 };
        assert_eq!(r#""127.0.0.1/32""#, serde_json::to_string(&ip).unwrap());
    }

    #[test]
    fn wireguard_peer_to_json() {
        let text = serde_json::to_string(
            &PeerInfo {
                public_key: WireguardPublicKey::try_from(PUBLIC_KEY).unwrap(),
                preshared_key: Some(EMPTY_PRESHARED_KEY),
                rx_bytes: Some(100_000_000_000),
                tx_bytes: Some(200_000_000_000),
                endpoint: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 60001))),
                persistent_keepalive: Some(600),
                last_handshake: Some(SystemTime::UNIX_EPOCH),
                allowed_ips: Some(vec![]),
            }
        );
        assert!(text.is_ok());
    }

    #[test]
    fn json_to_wireguard_peer() {
        let json = r#"
        {
            "public_key": "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k=",
            "preshared_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "rx_bytes": 1000000000,
            "tx_bytes": 2000000000,
            "endpoint": "127.0.0.1:60000",
            "persistent_keepalive": 3600,
            "allowed_ips": [
                "127.0.0.0/8",
                "192.168.0.0/16",
                "fd00::/64",
                "fe00::1/128"
            ],
            "last_handshake": 1
        }"#;

        let peer: PeerInfo = serde_json::from_str(json).unwrap();
        assert_eq!(&PUBLIC_KEY_BYTES, peer.public_key.0.as_bytes());
        assert_eq!(EMPTY_PRESHARED_KEY, peer.preshared_key.unwrap().as_slice());
        assert_eq!(peer.rx_bytes, Some(1_000_000_000));
        assert_eq!(peer.tx_bytes, Some(2_000_000_000));
        assert_eq!(peer.endpoint,
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 60000))));
        assert_eq!(peer.persistent_keepalive, Some(3600));
        assert_eq!(peer.last_handshake,
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1)));
    }

    #[test]
    fn panic_on_bad_preshared_key_length_on_peer_info_json() {
        let json = r#"
        {
            "public_key": "HUiXikVQV2/kdVygc6P+l19HINQX5M4SsfwSdLkAr0k=",
            "preshared_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }"#;
        let res = serde_json::from_str::<PeerInfo>(json);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().starts_with("invalid length 33, expected a key with 32 bytes"));
    }
}
