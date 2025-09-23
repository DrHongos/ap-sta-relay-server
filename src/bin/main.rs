#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use embedded_storage_async::nor_flash::NorFlash;
use esp_hal::clock::CpuClock;
use esp_hal::timer::systimer::SystemTimer;
use esp_hal::timer::timg::TimerGroup;
use log::info;
use alloc::string::{String, ToString};
use alloc::format;

use core::net::Ipv4Addr;
use core::str::FromStr;
use esp_storage::FlashStorage;
use sequential_storage::cache::NoCache;
use embassy_net::{
    Stack,
    IpListenEndpoint,
    Ipv4Cidr,
    Runner,
    StackResources,
    StaticConfigV4,
    tcp::TcpSocket,
};
use esp_wifi::wifi::{AccessPointConfiguration, Configuration, WifiDevice, ClientConfiguration, WifiController, WifiState, WifiEvent};
use esp_wifi::{init, EspWifiController};
use embedded_io_async::Write;

//use esp_hal::gpio::{DriveMode, Level, Output, OutputConfig};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

extern crate alloc;

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}


// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    // generator version: 0.5.0

    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 64 * 1024);    // some examples uses 72

    let timer0 = SystemTimer::new(peripherals.SYSTIMER);
    esp_hal_embassy::init(timer0.alarm0);

    info!("Embassy initialized!");

    let mut rng = esp_hal::rng::Rng::new(peripherals.RNG);
    let timer1 = TimerGroup::new(peripherals.TIMG0);
    
    let wifi_init = &*mk_static!(
        EspWifiController<'static>,
        init(timer1.timer0, rng.clone()).unwrap()
    );
    
    let (mut controller, interfaces) = esp_wifi::wifi::new(&wifi_init, peripherals.WIFI)
        .expect("Failed to initialize WIFI controller");

    let wifi_ap_device = interfaces.ap;
//    let wifi_sta_device = interfaces.sta;
    let gw_ip_addr_str = "192.168.2.1";
    let gw_ip_addr = Ipv4Addr::from_str(gw_ip_addr_str).unwrap();

    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(gw_ip_addr, 24),
        gateway: Some(gw_ip_addr),
        dns_servers: Default::default(),
    });
//    let sta_config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_device,
        ap_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );
    /* 
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_device,
        sta_config,
        mk_static!(StackResources<4>, StackResources::<4>::new()),
        seed,
    ); 
    */
// Reading config
    
    // cannot use nvs without the safe api
    let mut flash = embassy_embedded_hal::adapter::BlockingAsync::new(FlashStorage::new());


    // use this to set the client_config based on wifi config
    let mut start_wifi = false;
    let client_config = if let Some((ssid, bssid)) = get_wifi_config(&mut flash).await {
        info!("WiFi configured! {}:{}", ssid, bssid);
        start_wifi = true;
        Configuration::Mixed(
            ClientConfiguration {
                ssid: ssid.into(),
                password: bssid.into(),
                ..Default::default()
            },
            AccessPointConfiguration {
                ssid: "esp-wifi".into(),
                ..Default::default()
            },
        )
    } else {
        info!("Wifi not configured yet");
        Configuration::AccessPoint(
            AccessPointConfiguration {
                ssid: "esp-wifi".into(),
                ..Default::default()
            }
        )
    };
    controller.set_configuration(&client_config).unwrap();

   // let led = Output::new(peripherals.GPIO8, Level::Low, OutputConfig::default());
   // spawner.spawn(blink(led)).ok();

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(ap_runner)).ok();

    if start_wifi {
        info!("Connecting to WiFi network");
        /* 
        //spawner.spawn(net_task(sta_runner)).ok();
        let sta_address = loop {
            if let Some(config) = sta_stack.config_v4() {
                let address = config.address.address();
                info!("Got IP: {}", address);
                break address;
            }
            info!("Waiting for IP...");
            Timer::after(Duration::from_millis(500)).await;
        };
        loop {
            if ap_stack.is_link_up() {
                break;
            }
            Timer::after(Duration::from_millis(500)).await;
        }
     */
    } else {
        spawner.spawn(run_dhcp(ap_stack, gw_ip_addr_str)).ok();

    }

    // prepare pages (and later relays)
    const PAGE: &str = include_str!("../html/index.html");
    const CRED_PAGE: &str = include_str!("../html/ap_credentials.html");

    let mut ap_rx_buffer = [0; 1536];
    let mut ap_tx_buffer = [0; 1536];
    let mut socket = TcpSocket::new(ap_stack, &mut ap_rx_buffer, &mut ap_tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(10)));

/* 
    let mut sta_rx_buffer = [0; 1536];
    let mut sta_tx_buffer = [0; 1536];
    let mut sta_server_socket = TcpSocket::new(
        sta_stack,
        &mut sta_server_rx_buffer,
        &mut sta_server_tx_buffer,
    );
    sta_server_socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));
 */

    info!("Connect to the AP `esp-wifi` and point your browser to http://192.168.2.1:8080/");
    
    loop {
        // TODO: this is only AP
        // use it to set wifi credentials and restart

        // in dual mode, check connection, if fails, do this again
        // if connects to wifi, then present PAGE with the relays control 

        info!("Wait for connection...");
        let r = socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 8080,
            })
            .await;
        info!("Connected...");

        if let Err(e) = r {
            info!("connect error: {:?}", e);
            continue;
        }

        let mut buffer = [0u8; 1024];
        let mut pos = 0;
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    info!("read EOF");
                    break;
                }
                Ok(len) => {
                    let to_print =
                        unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };

                    if to_print.contains("\r\n\r\n") {
                        info!("{}", to_print);
                        break;
                    }

                    pos += len;
                }
                Err(e) => {
                    info!("read error: {:?}", e);
                    break;
                }
            };
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
            CRED_PAGE.len(),
            CRED_PAGE
        );
        let r = socket.write_all(resp.as_bytes()).await;

        if let Err(e) = r {
            info!("write error: {:?}", e);
        }

        let r = socket.flush().await;
        if let Err(e) = r {
            info!("flush error: {:?}", e);
        }
        Timer::after(Duration::from_millis(1000)).await;

        socket.close();
        Timer::after(Duration::from_millis(1000)).await;

        socket.abort();

    }


}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

async fn get_wifi_config(mut flash: &mut impl NorFlash) -> Option<(String, String)> {
    let mut ssid_buffer = [0; 32];
    let mut bssid_buffer = [0; 32];
    const NVS_FLASH_RANGE: core::ops::Range<u32> = 0x9000..0xF000;

    if let Some(ssid) = sequential_storage::map::fetch_item::<u8, &[u8], _>(
        &mut flash,
        NVS_FLASH_RANGE.clone(),
        &mut NoCache::new(),
        &mut ssid_buffer,
        &0,
    ).await.unwrap() {
        let ssid_recovered = core::str::from_utf8(&ssid).unwrap();
        if let Some(bssid) = sequential_storage::map::fetch_item::<u8, &[u8], _>(
            &mut flash,
            NVS_FLASH_RANGE.clone(),
            &mut NoCache::new(),
            &mut bssid_buffer,
            &1,
        ).await.unwrap() {
            let bssid_recovered = core::str::from_utf8(&bssid).unwrap();
            //  if config exists -> connect wifi and launch sever 
            Some((ssid_recovered.to_string(), bssid_recovered.to_string()))
        } else {
            None
        }
    } else {
        None
    }
}
/* 
dual mode connection
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("start connection task");
    info!("Device capabilities: {:?}", controller.capabilities());

    info!("Starting wifi");
    controller.start_async().await.unwrap();
    info!("Wifi started!");

    loop {
        match esp_wifi::wifi::ap_state() {
            WifiState::ApStarted => {
                info!("About to connect...");

                match controller.connect_async().await {
                    Ok(_) => {
                        // wait until we're no longer connected
                        controller.wait_for_event(WifiEvent::StaDisconnected).await;
                        info!("STA disconnected");
                    }
                    Err(e) => {
                        info!("Failed to connect to wifi: {e:?}");
                        Timer::after(Duration::from_millis(5000)).await
                    }
                }
            }
            _ => return,
        }
    }
} 
*/

//this is the fn in the only AP example (https://github.com/esp-rs/esp-hal/blob/esp-hal-v1.0.0-rc.0/examples/src/bin/wifi_embassy_access_point.rs)
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("start connection task");
    info!("Device capabilities: {:?}", controller.capabilities());
    loop {
        match esp_wifi::wifi::wifi_state() {
            WifiState::ApStarted => {
                // wait until we're no longer connected
                controller.wait_for_event(WifiEvent::ApStop).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::AccessPoint(AccessPointConfiguration {
                ssid: "esp-wifi".try_into().unwrap(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            info!("Starting wifi");
            controller.start_async().await.unwrap();
            info!("Wifi started!");
        }
    }
}

/*  
   TEST WRITES (convert to a function for later)
    let mut ssid_buffer = [0; 32];
    let mut bssid_buffer = [0; 32];
    const NVS_FLASH_RANGE: core::ops::Range<u32> = 0x9000..0xF000;
    let ssid_value = alloc::string::String::from("my_wifi");
    let bssid_value = alloc::string::String::from("my_password");
    sequential_storage::map::store_item(
        &mut flash,
        NVS_FLASH_RANGE.clone(),
        &mut NoCache::new(),
        &mut ssid_buffer,
        &0,
        &ssid_value.as_bytes(),
    ).await.unwrap();
    sequential_storage::map::store_item(
        &mut flash,
        NVS_FLASH_RANGE.clone(),
        &mut NoCache::new(),
        &mut bssid_buffer,
        &1,
        &bssid_value.as_bytes(),
    ).await.unwrap();
 */

#[embassy_executor::task]
async fn run_dhcp(stack: Stack<'static>, gw_ip_addr: &'static str) {
    use core::net::{Ipv4Addr, SocketAddrV4};

    use edge_dhcp::{
        io::{self, DEFAULT_SERVER_PORT},
        server::{Server, ServerOptions},
    };
    use edge_nal::UdpBind;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let ip = Ipv4Addr::from_str(gw_ip_addr).expect("dhcp task failed to parse gw ip");

    let mut buf = [0u8; 1500];

    let mut gw_buf = [Ipv4Addr::UNSPECIFIED];

    let buffers = UdpBuffers::<3, 1024, 1024, 10>::new();
    let unbound_socket = Udp::new(stack, &buffers);
    let mut bound_socket = unbound_socket
        .bind(core::net::SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            DEFAULT_SERVER_PORT,
        )))
        .await
        .unwrap();
    
    info!("Starting DHCP server");
    loop {
        _ = io::server::run(
            &mut Server::<_, 64>::new_with_et(ip),
            &ServerOptions::new(ip, Some(&mut gw_buf)),
            &mut bound_socket,
            &mut buf,
        )
        .await
        .inspect_err(|e| log::warn!("DHCP server error: {e:?}"));
        Timer::after(Duration::from_millis(500)).await;
    }
}