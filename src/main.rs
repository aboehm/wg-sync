#[macro_use] extern crate rocket;

use wg_sync::{
    api::{
        status_ok,
        PeerInfo
    },
    WireguardManager,
};
use rocket::{
    State,
    http::Status,
    serde::json::Json,
};
use std::collections::HashMap;
use reqwest::IntoUrl;

async fn catch_peers_from_url<T>(url: T) -> Result<Vec<PeerInfo>, String>
where
    T: IntoUrl,
{
    reqwest::get(url)
        .await
        .map_err(|_| "Can't download peer config".to_string())?
        .json()
        .await
        .map_err(|_| "Can't parse returned json".to_string())
}

#[get("/interfaces")]
async fn interfaces(man: &State<WireguardManager>) -> (Status, Json<serde_json::Value>) {
    let list = man.list().await.unwrap();

    let mut info_list = vec![];
    let mut err_list = HashMap::new();
 
    for link in list.iter() {
        match man.get(link).await {
            Ok(info) => {
                info_list.push(info);
            },
            Err(err) => {
                err_list.insert(link, err).unwrap();
            },
        };
    }

    let json = Json(serde_json::json!({
        "interfaces": info_list,
        "errors": err_list,
    }));

   (Status::Ok, json)
}

#[get("/interface/<interface>")]
async fn get_device(man: &State<WireguardManager>, interface: &str) -> (Status, Json<serde_json::Value>) {
    match man.get(interface).await {
        Ok(info) => status_ok("interface", Some(info)),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({ "error": err }))),
    }
}

#[post("/interface/<interface>")]
async fn add_device(man: &State<WireguardManager>, interface: &str) -> (Status, Json<serde_json::Value>) {
    match man.add(interface).await {
        Ok(_) => (Status::Ok, Json(serde_json::json!({"status": "ok"}))),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({
            "status": "error",
            "error": err,
        }))),
    }
}

#[delete("/interface/<interface>")]
async fn delete_device(man: &State<WireguardManager>, interface: &str) -> (Status, Json<serde_json::Value>) {
    match man.delete(interface).await {
        Ok(_) => (Status::Ok, Json(serde_json::json!({"status": "ok"}))),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({
            "status": "error",
            "error": err,
        }))),
    }
}

#[patch("/interface/<interface>", format = "json", data = "<config>")]
async fn update_device(man: &State<WireguardManager>, interface: &str, config: Json<wg_sync::api::Device>) -> (Status, Json<serde_json::Value>) {
    match man.configure(interface, &config).await {
        Ok(_) => (Status::Ok, Json(serde_json::json!({"status": "ok"}))),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({
            "status": "error",
            "error": err,
        }))),
    }
}

#[get("/interface/<interface>/peers")]
async fn get_device_peers(man: &State<WireguardManager>, interface: &str) -> (Status, Json<serde_json::Value>)
{
    match man.get(interface).await {
        Ok(device) => (Status::Ok, Json(serde_json::json!({
            "status": "ok",
            "peers": device.peers,
        }))),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({
            "status": "error",
            "error": err
        }))),
    }
}

#[post("/interface/<interface>/peers", format = "json", data = "<peers>")]
async fn configure_device_peers(man: &State<WireguardManager>, interface: &str, peers: Json<Vec<PeerInfo>>) -> (Status, Json<serde_json::Value>)
{
    match man.configure_peers(interface, &peers).await {
        Ok(_) => (Status::Ok, Json(serde_json::json!({
            "status": "ok",
        }))),
        Err(err) => (Status::BadRequest, Json(serde_json::json!({
            "status": "error",
            "error": err
        }))),
    }
}

use clap::{value_parser, Arg, ArgGroup, ArgMatches, Command, Parser};

#[derive(Debug)]
struct Config {
    pub port: u16,
    pub interfaces: Vec<Interface>,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let args = Command::new("wg-sync")
            .args(&[
                Arg::new("port")
                    .long("port")
                    .short('p')
                    .value_parser(value_parser!(u16))
                    .takes_value(true)
                    .default_missing_value("50777")
                    .help("Port where service listen"),
                Arg::new("interface")
                    .long("iface")
                    .short('i')
                    .takes_value(true)
                    .multiple(true)
                    .help("Name of the interface"),
                Arg::new("interval")
                    .long("interval")
                    .short('t')
                    .value_parser(value_parser!(u32))
                    .takes_value(true)
                    .multiple(true)
                    .help("Interval in seconds to update the peers"),
                Arg::new("peer-url")
                    .long("peer-url")
                    .short('u')
                    .takes_value(true)
                    .multiple(true)
                    .help("URL to peers listing"),
            ])
            .get_matches();

        let ifaces = args.get_many::<String>("interface")
            .map(|p| p.into_iter().collect())
            .unwrap_or(vec![]);

        let intervals = args.get_many::<u32>("interval")
            .map(|p| p.into_iter().collect())
            .unwrap_or(vec![]);

        let peer_urls = args.get_many::<String>("peer-url")
            .map(|p| p.into_iter().collect())
            .unwrap_or(vec![]);

        if intervals.len() > ifaces.len() {
            return Err("Too much intervals given. The interval must maps to the interface".to_string())
        }

        let mut ifaces_config = vec![];
        let mut interval_idx = 0;
        let mut peer_url_idx = 0;
        for iface_idx in 0..ifaces.len() {
            let iface = ifaces[iface_idx];
            let interval = intervals.get(interval_idx);
            let peer_url = peer_urls.get(peer_url_idx);

            if interval.is_some() {
                interval_idx += 1;
            }

            if peer_url.is_some() {
                peer_url_idx += 1;
            }

            ifaces_config.push(Interface {
                name: iface.to_string(),
                interval: interval.map(|v| **v).unwrap_or(60u32),
                url: peer_url.map(|i| i.to_string()),
            })
        }

        Ok(Config {
            port: *args.get_one::<u16>("port").expect("Port must be a number"),
            interfaces: ifaces_config,
        })
    }
}

#[derive(Debug)]
struct Interface {
    name: String,
    interval: u32,
    url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();
    let mut manager = WireguardManager::connect()?;

    let config = Config::parse().unwrap();

    let rk_config = rocket::Config {
        port: config.port,
        ..rocket::Config::debug_default()
    };

    let _rocket = rocket::custom(&rk_config)
        .mount("/", routes![
            interfaces,
            add_device,
            delete_device,
            get_device,
            get_device_peers,
            configure_device_peers,
            update_device,
        ])
        .manage(manager)
        .ignite()
        .await
        .map_err(|err| format!("Can't start service: {:}", err))?
        .launch()
        .await
        .map_err(|err| format!("Can't run service: {:}", err))?;
    Ok(())
}
