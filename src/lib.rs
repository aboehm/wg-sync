pub mod api;

use serde::{
    de::Error,
    Deserialize, Deserializer, Serializer,
};

use wireguard_uapi::{
    RouteSocket,
    linux::WgSocket,
};

pub use wireguard_uapi::get::AllowedIp;

use api::{Device, PeerInfo, WireguardPublicKey};

use std::sync::{Arc, Mutex};

pub fn serialize_optional_bytes<S>(data: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
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

pub fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
  D: Deserializer<'de>,
{
    let val = String::deserialize(deserializer)?;
    base64::decode(val)
        .map(|val| Some(val))
        .map_err(|_| D::Error::custom("Can't decode base64 value"))
}

struct ControlSockets {
    route_socket: RouteSocket,
    wg_socket: WgSocket,
}

impl ControlSockets {
    fn connect() -> Result<Self, String> {
        let route_socket = RouteSocket::connect()
            .map_err(|err| format!("Can't open a route control socket: {:?}", err))?;
        let wg_socket = WgSocket::connect()
            .map_err(|err| format!("Can't open a wireguard control socket: {:?}", err))?;
        Ok(ControlSockets {
            route_socket,
            wg_socket,
        })
    }

    fn control<F, R, E>(&mut self, f: F) -> Result<R, E>
    where  
        F: FnOnce(&mut RouteSocket, &mut WgSocket) -> Result<R, E>,
    {
        f(&mut self.route_socket, &mut self.wg_socket)
    }
}

pub struct WireguardManager (Arc<Mutex<ControlSockets>>);

impl WireguardManager {
    pub fn connect() -> Result<Self, String> {
        log::info!("Connecting to kernel control sockets");
        Ok(WireguardManager(Arc::new(Mutex::new(ControlSockets::connect()
            .map_err(|err| {
                log::error!("Problem while connecting to control sockets: {:?}", err);
                err
            })?))))
    }
    
    pub async fn add(&self, iface: &str) -> Result<(), String> {
        log::info!("Adding new interface {}", iface);
        self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|rt, _| rt.add_device(iface))
            .map_err(|err| {
                log::error!("Error while adding device {}: {:?}", iface, err);
                format!("Can't create device {}: {:?}", iface, err)
            })
    }

    pub async fn delete(&self, iface: &str) -> Result<(), String> {
        log::info!("Deleting interface {}", iface);
        self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|rt, _| rt.del_device(iface))
            .map_err(|err| {
                log::error!("Error while deleting device {}: {:?}", iface, err);
                format!("Can't delete device {}: {:?}", iface, err)
            })
    }

    pub async fn configure(&self, iface: &str, device: &Device) -> Result<(), String> {
        log::info!("Configure device {} with", iface);

        let mut peers = vec![];
        let mut flags = vec![];

        if device.peers.is_some() {
            flags.push(wireguard_uapi::linux::set::WgDeviceF::ReplacePeers);
            for peer in device.peers.as_ref().unwrap().iter() {
                peers.push(peer.into());
            }
        }

        self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|_, wr| wr.set_device(wireguard_uapi::set::Device {
                interface: wireguard_uapi::DeviceInterface::from_name(iface),
                private_key: device.private_key.as_ref().map(|key| key.as_bytes()),
                flags: flags,
                listen_port: device.listen_port,
                fwmark: device.fwmark,
                peers,
            }))
            .map_err(|err| format!("Problem during configuration of {}: {:}", iface, err))
    }
    
    pub async fn list(&self) -> Result<Vec<String>, String> {
        self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|rt, _| rt.list_device_names())
            .map_err(|err| format!("Can't enlist interfaces {:?}", err))
    }

    pub async fn get(&self, iface: &str) -> Result<Device, String> {
        let device = self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|_, wr| wr.get_device(wireguard_uapi::DeviceInterface::from_name(iface)))
            .map_err(|err| format!("Can't get interface {}: {:?}", iface, err))?;
        Device::try_from(device)
    }

    pub async fn get_peer(&self, iface: &str, peer_key: &WireguardPublicKey) -> Result<Option<PeerInfo>, String> {
        let device: Device = self.get(iface).await?;

        if let Some(peers) = device.peers.as_ref() {
            for peer in peers.iter() {
                if &(peer.public_key) == peer_key {
                    return Ok(Some(peer.clone()))
                }
            }
        }

        Ok(None)
    }

    pub async fn configure_peers(&self, iface: &str, peers: &[PeerInfo]) -> Result<(), String> {
        self.0.lock()
            .expect("Can't gather lock on sockets")
            .control(|_, wr| wr.set_device(wireguard_uapi::set::Device {
                interface: wireguard_uapi::DeviceInterface::from_name(iface),
                private_key: None,
                flags: vec![wireguard_uapi::linux::set::WgDeviceF::ReplacePeers],
                listen_port: None,
                fwmark: None,
                peers: peers.to_vec().iter().map(|p| p.into()).collect(),
            }))
            .map_err(|err| format!("Can't configure peers for interface {}: {:?}", iface, err))
    }
}
