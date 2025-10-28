#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::tcp::client::{TcpClient, TcpClientState};
use embassy_time::{Duration, Timer};
use embedded_storage_async::nor_flash::NorFlash;
use esp_hal::clock::CpuClock;
use esp_hal::timer::systimer::SystemTimer;
use esp_hal::timer::timg::TimerGroup;
use log::info;
use alloc::string::{String, ToString};
use alloc::format;
use rust_mqtt::client::client::MqttClient;
use rust_mqtt::client::client_config::ClientConfig;
use rust_mqtt::utils::rng_generator::CountingRng;

use core::net::Ipv4Addr;
use core::str::{FromStr, from_utf8};
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
use static_cell::StaticCell;

use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    text::Text,
};

use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig};
use esp_hal::i2c::master::{Config, I2c};

use embassy_sync::channel::Channel;
use  embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

use embedded_nal_async::TcpConnect;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

extern crate alloc;

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: StaticCell<$t> = StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

static CHANNEL: Channel<CriticalSectionRawMutex, u8, 8> = Channel::new();
static MQTT_CHANNEL: Channel<CriticalSectionRawMutex, (String, String), 5> = Channel::new(); // TODO: Message type (topic, message) ??
// TODO: this should be configurable and on NVS
const TOPIC: &str = "ap-sta-relay-server";

static RELAYS_CELL: StaticCell<Relays> = StaticCell::new();

#[derive(Clone, Copy)]
pub struct RelayState {
    pub s1: bool,
    pub s2: bool,
    pub s3: bool,
}
impl RelayState {
    /* 
    fn on(&mut self, idx: u8) {
        match idx {
            1 => { self.s1 = true; }
            2 => { self.s2 = true; }
            3 => { self.s3 = true; }
            _ => {}
        }
    }

    fn off(&mut self, idx: u8) {
        match idx {
            1 => { self.s1 = false; }
            2 => { self.s2 = false; }
            3 => { self.s3 = false; }
            _ => {}
        }
    } 
    */
    fn json_status(&self) -> heapless::String<128> {
        // use heapless string since no_std
        let mut s = heapless::String::<128>::new();
        use core::fmt::Write;
        let _ = write!(
            s,
            "{{\"relay1\":{},\"relay2\":{},\"relay3\":{}}}",
            self.s1, self.s2, self.s3
        );
        s
    }
}

static STATE: Mutex<CriticalSectionRawMutex, RelayState> = Mutex::new(RelayState {
    s1: false,
    s2: false,
    s3: false
});

pub struct Relays {
    pub r1: Output<'static>,
    pub r2: Output<'static>,
    pub r3: Output<'static>,
}
impl Relays {
    fn new(r1: Output<'static>, r2: Output<'static>, r3: Output<'static>) -> Self {
        Self { r1, r2, r3  }
    }
/* 
    fn on(&mut self, idx: u8) {
        match idx {
            1 => { self.r1.set_high(); }
            2 => { self.r2.set_high(); }
            3 => { self.r3.set_high(); }
            _ => {}
        }
    }

    fn off(&mut self, idx: u8) {
        match idx {
            1 => { self.r1.set_low(); }
            2 => { self.r2.set_low(); }
            3 => { self.r3.set_low(); }
            _ => {}
        }
    }
 */
}


esp_bootloader_esp_idf::esp_app_desc!();
const NVS_FLASH_RANGE: core::ops::Range<u32> = 0x9000..0xF000;

static RX_BUFFER: StaticCell<[u8; 1536]> = StaticCell::new();
static TX_BUFFER: StaticCell<[u8; 1536]> = StaticCell::new();

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 64 * 1024);    // some examples uses 72

    let timer0 = SystemTimer::new(peripherals.SYSTIMER);
    esp_hal_embassy::init(timer0.alarm0);

    info!("Embassy initialized!");

    // display inclusion
    let i2c = I2c::new(peripherals.I2C0, Config::default()).unwrap()
         .with_sda(peripherals.GPIO8)
         .with_scl(peripherals.GPIO9);
    
    let interface = I2CDisplayInterface::new(i2c);
    let mut display: Ssd1306<I2CInterface<I2c<'_, esp_hal::Blocking>>, DisplaySize128x64, ssd1306::mode::BufferedGraphicsMode<DisplaySize128x64>> = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    display.init().unwrap();
    set_text_display(&mut display, "Welcome! instructions are loading..");

    let mut rng = esp_hal::rng::Rng::new(peripherals.RNG);
    let timer1 = TimerGroup::new(peripherals.TIMG0);
    
    let wifi_init = &*mk_static!(
        EspWifiController<'static>,
        init(timer1.timer0, rng.clone()).unwrap()
    );
    
    let (mut controller, interfaces) = esp_wifi::wifi::new(&wifi_init, peripherals.WIFI)
        .expect("Failed to initialize WIFI controller");

    let wifi_ap_device = interfaces.ap;
    let wifi_sta_device = interfaces.sta;

    let gw_ip_addr_str = "192.168.2.1";
    let gw_ip_addr = Ipv4Addr::from_str(gw_ip_addr_str).unwrap();
    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(gw_ip_addr, 24),
        gateway: Some(gw_ip_addr),
        dns_servers: Default::default(),
    });
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // cannot use nvs without the safe api
    let mut flash = embassy_embedded_hal::adapter::BlockingAsync::new(FlashStorage::new());
 
    let mut start_wifi = false;
    let client_config = if let Some((ssid, bssid)) = get_wifi_config(&mut flash).await {
        let ssidn =  bytes_to_clean_string(ssid.as_bytes()).unwrap_or(String::new());
        let bssidn =  bytes_to_clean_string(bssid.as_bytes()).unwrap_or(String::new());
        
        set_text_display(&mut display, "Wifi is configured");
        start_wifi = true;
        Configuration::Client(
            ClientConfiguration {
                ssid: ssidn.into(),
                password: bssidn.into(),
                ..Default::default()
            })
    } else {
        info!("Wifi not configured yet, starting only AP");
        set_text_display(&mut display, "Wifi is not configured");
        Configuration::AccessPoint(
            AccessPointConfiguration {
                ssid: "esp-wifi".into(),
                ..Default::default()
            }
        )
    };
    controller.set_configuration(&client_config).unwrap();

    // app logic
    let r1 = Output::new(peripherals.GPIO5, Level::Low, OutputConfig::default());
    let r2 = Output::new(peripherals.GPIO6, Level::Low, OutputConfig::default());
    let r3 = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());
    let relays: &'static mut Relays = RELAYS_CELL.init(
        Relays::new(r1, r2, r3)
    );
    
    spawner.spawn(handle_relays(relays)).unwrap();

    // TODO: create struct for buttons
    // TODO: add more buttons
    let b1= Input::new(peripherals.GPIO2, InputConfig::default().with_pull(esp_hal::gpio::Pull::Up));
    let b2 = Input::new(peripherals.GPIO3, InputConfig::default().with_pull(esp_hal::gpio::Pull::Up));
    let b3 = Input::new(peripherals.GPIO4, InputConfig::default().with_pull(esp_hal::gpio::Pull::Up));
    spawner.spawn(manual_buttons(b1, b2, b3)).unwrap(); 


    let rx_buf = RX_BUFFER.init([0; 1536]);
    let tx_buf = TX_BUFFER.init([0; 1536]);
    let mut buffer = [0u8; 1024];
    
    // html to serve
    let page = if start_wifi { include_str!("../html/index.html") } else { include_str!("../html/ap_credentials.html") };
        
    // refactored this both cases into tasks (didnt work well)
    if !start_wifi {
        info!("Spawning ap");
        let (ap_stack, ap_runner) = embassy_net::new(
            wifi_ap_device,
            ap_config,
            mk_static!(StackResources<3>, StackResources::<3>::new()),
            seed,
        ); 
        set_text_display(&mut display, "Connect to 'esp-wifi', open 192.168.2.1:8080, to configure your LAN");
        spawner.spawn(ap_connection(controller)).ok();
        spawner.spawn(run_dhcp(ap_stack, gw_ip_addr_str)).ok();
        spawner.spawn(net_task(ap_runner)).ok();
    
        let mut socket = TcpSocket::new(ap_stack, rx_buf, tx_buf);
        socket.set_timeout(Some(Duration::from_secs(10)));
        loop {
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
    
            let mut pos = 0;
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) => {
                        info!("read EOF");
                        break;
                    }
                    Ok(len) => {
                        let to_print = unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };
                        let first_line = to_print.lines().next().unwrap_or("");
                        if first_line.starts_with("POST /save HTTP/1.1") {
                            info!("Received {}", first_line);
                            if let Some(body) = extract_body(to_print) {
                                if let Some((ssid, bssid)) = parse_form(body) {
                                    info!("Storing ssid:{} & bssid: {}", ssid, bssid);
                                    store_credentials(&mut flash, ssid, bssid).await;
                                    info!("restart..");
                                    esp_hal::system::software_reset();                           
                                }
                            }
                        }                    
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
            // prepare response
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
                page.len(),
                page
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
    } else {
        // BUG if enters this branch, AP wont work anymore (stuck in "Obtainig IP")
        // and printing: WARN - Unable to allocate 1700 bytes
        set_text_display(&mut display, "Connecting to Wifi");
        let sta_config = embassy_net::Config::dhcpv4(Default::default());
        let (sta_stack, sta_runner) = embassy_net::new(
            wifi_sta_device,
            sta_config,
            mk_static!(StackResources<4>, StackResources::<4>::new()),
            seed,
        ); 
        spawner.spawn(sta_connection(controller)).ok();
        spawner.spawn(net_task(sta_runner)).ok();
        loop {
            if sta_stack.is_link_up() {
                break;
            }
            info!("STA not connected");
            Timer::after(Duration::from_millis(500)).await;
        }

        let max_connection_attempts = 40;
        let mut attempt = 0;
        let sta_address = loop {
            if let Some(config) = sta_stack.config_v4() {
                let address = config.address.address();
                info!("Got IP: {}", address);
                break address;
            }
            info!("Waiting for IP...");
            Timer::after(Duration::from_millis(500)).await;
            attempt +=1;
            if attempt == max_connection_attempts {
                info!("Incorrect credentials, deleting..");
                let _ = sequential_storage::erase_all(&mut flash, NVS_FLASH_RANGE).await;
                esp_hal::system::software_reset();
            }
        };
        info!("Connected to {}", sta_address);
        let ip_text = format!("Go to , {}:8080", sta_address);
        set_text_display(&mut display, &ip_text);

        let sta_stack_static = mk_static!(Stack, sta_stack.clone());
        spawner.spawn(mqtt_task(&*sta_stack_static)).unwrap();

        let mut socket = TcpSocket::new(sta_stack, rx_buf, tx_buf);
        socket.set_timeout(Some(Duration::from_secs(10)));

        loop {
            let _r = socket.accept(IpListenEndpoint {
                    addr: None,
                    port: 8080,
                }
            )
            .await;
            info!("Connected...");
           
            let n = socket.read(&mut buffer).await.unwrap_or(0);
            if n == 0 {
                continue;
            }
            let req = core::str::from_utf8(&buffer[..n]).unwrap_or("");
            let first_line = req.lines().next().unwrap_or("");  // Route by first line, e.g.: "GET /relay1?on HTTP/1.1"
            let mut sent = false;
            if first_line.starts_with("GET / ") {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
                    page.len(),
                    page
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
                sent = true;
            } else if first_line.starts_with("GET /status") {
                let state = STATE.lock().await;
                let body = state.json_status();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
                sent = true;
            
            } else {
                // TODO: what to do with flags? 
                match first_line {
                    l if l.starts_with("GET /relay1")  => { CHANNEL.send(1).await;  sent = send_ok(&mut socket).await; }
                    l if l.starts_with("GET /relay2")  => { CHANNEL.send(2).await;  sent = send_ok(&mut socket).await; }
                    l if l.starts_with("GET /relay3")  => { CHANNEL.send(3).await;  sent = send_ok(&mut socket).await; }
                    _ => {}
                }
            }

            if !sent {
                // 404 for anything else
                let body = "Not Found";
                let resp = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
            }
                        
            log::info!("Response sent, closing socket");
        }
    }
}

// TODO: handle mqtt messaging better
// maybe the json_status for each button in the loop directly?
#[embassy_executor::task]
async fn handle_relays(relays: &'static mut Relays) {
    let mut handle = async |idx: u8| {
        let mut state = STATE.lock().await;
        match idx {
            1 => {
                relays.r1.toggle();
                state.s1 = !state.s1;
                let m = if state.s1 == true { "relay1: ON" } else { "relay1: OFF" };
                MQTT_CHANNEL.send((TOPIC.to_string(), m.to_string())).await;
            },
            2 => {
                relays.r2.toggle();
                state.s2 = !state.s2;
                let m = if state.s2 == true { "relay2: ON" } else { "relay2: OFF" };
                MQTT_CHANNEL.send((TOPIC.to_string(), m.to_string())).await;
            },
            3 => {
                relays.r3.toggle();
                state.s3 = !state.s3;
                let m = if state.s3 == true { "relay3: ON" } else { "relay3: OFF" };
                MQTT_CHANNEL.send((TOPIC.to_string(), m.to_string())).await;
            },
            _ => {}
        }
    };
    loop {
        let num = CHANNEL.receive().await;
        handle(num).await;
    }

}


// make the mqtt client configurable (endpoint, topics, etc) on NVS
// create the first message (discovery retain=true) for a broker indexing
// create a config web page for the mqtt client & settings
// topics: set & state for each relay -> name/r1|2|3/set|state (set name on config?)
#[embassy_executor::task]
async fn mqtt_task(stack: &'static Stack<'static>) {
    info!("Start mqtt task");
    const MQTT_BUFFER_SIZE: usize = 1024;
    let mut mqtt_buf = [0; MQTT_BUFFER_SIZE];
    let mut recv_buffer = [0u8; MQTT_BUFFER_SIZE];
    loop {
        if !stack.is_link_up() {
            Timer::after(Duration::from_secs(1)).await;
            continue;
        }
        let mqtt_config: ClientConfig<'_, 5, CountingRng> = ClientConfig::new(
            rust_mqtt::client::client_config::MqttVersion::MQTTv5, 
            CountingRng(124356)         // TODO: use a real random
        ); 
        let addr = core::net::SocketAddr::new(Ipv4Addr::new(192, 168, 18, 9).into(), 1883);
        
        let mut tcp_state: TcpClientState<3, MQTT_BUFFER_SIZE, MQTT_BUFFER_SIZE> = TcpClientState::new();
        let tcp_client = TcpClient::new(*stack, &mut tcp_state);
        let tcp_connection = tcp_client.connect(addr).await.unwrap();
        // create a mqtt client
        let mut mqtt_client = MqttClient::new(
            tcp_connection, 
            &mut mqtt_buf, 
            MQTT_BUFFER_SIZE, 
            &mut recv_buffer, 
            MQTT_BUFFER_SIZE, 
            mqtt_config
        );
        // connect to a broker
        mqtt_client.connect_to_broker().await.unwrap();
        
        // TODO send discovery message
        
        // subscribe to command topics
        info!("Subscribing");
        let mut topic_set = String::new();
        topic_set.push_str(TOPIC);
        topic_set.push_str("/set");
        //mqtt_client.subscribe_to_topic(&topic_set).await.unwrap();

        // start client loop
        info!("Starting mqtt messages");
        loop {
            match select(
                MQTT_CHANNEL.receive(),
                mqtt_client.receive_message()
            ).await {
                Either::First((topic, payload)) => {
                    mqtt_client.send_message(
                        &topic, 
                        payload.as_bytes(), 
                    rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1, 
                    false
                    ).await.unwrap();
                },
                Either::Second(res) => {
                    info!("Received: {:?}", res);
                    // TOFIX: this code below seems to break everything (actually from wifi connection)
                    
                    match res {
                        Ok((topic, payload)) => {
                            // filter topic for SET commands
                            // ignore others
                            //if let Some((prefix, command)) = topic.rsplit_once("/") {
                            //    match command {
                            //        "set" => {
                            // get relay to toggle on the payload
                            // and send command through CHANNEL
                                let relay_idx = u8::from_str_radix(
                                    from_utf8(payload).unwrap(), 
                                    10).unwrap_or(0);   // TODO: default case is noop 
                                CHANNEL.send(relay_idx).await;
                                //    };
                            //        "state" => {info!("TODO: get states")},
                            //        _ => break
                            //    }
                            //}
                        },
                        Err(_) => break,
                    }
                    
                }
            }
        }    
    }
}

#[embassy_executor::task]
async fn manual_buttons(b1: Input<'static>, b2: Input<'static>, b3: Input<'static>) {
    loop  {
        if b1.level() == Level::Low {
            info!("R1 button pressed!");
            while b1.level() == Level::Low {
                Timer::after(Duration::from_millis(10)).await;
            }
            CHANNEL.send(1).await;
            Timer::after(Duration::from_millis(100)).await; // debounce
        }
        if b2.level() == Level::Low {
            info!("R2 button pressed!");
            while b2.level() == Level::Low {
                Timer::after(Duration::from_millis(10)).await;
            } 
            CHANNEL.send(2).await;
            Timer::after(Duration::from_millis(100)).await;
        }
        if b3.level() == Level::Low {
            info!("R3 button pressed!");
            while b3.level() == Level::Low {
                Timer::after(Duration::from_millis(10)).await;
            } 
            CHANNEL.send(3).await;
            Timer::after(Duration::from_millis(100)).await;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

fn set_text_display(
    display: &mut Ssd1306<I2CInterface<I2c<'_, esp_hal::Blocking>>, DisplaySize128x64, ssd1306::mode::BufferedGraphicsMode<DisplaySize128x64>>,
    text: &str) {
    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    display.clear(BinaryColor::Off).unwrap();
    let parts = text.split(",");
    let mut y = 16;
    for p in parts {
        Text::new(p.trim(), Point::new(0, y), style)
            .draw(display)
            .unwrap();
        y += 16;
    }
    display.flush().unwrap();
}

async fn get_wifi_config(mut flash: &mut impl NorFlash) -> Option<(String, String)> {
    let mut ssid_buffer = [0; 32];
    let mut bssid_buffer = [0; 32];

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

async fn store_credentials(mut flash: &mut impl NorFlash, ssid: String, bssid: String) {
    const NVS_FLASH_RANGE: core::ops::Range<u32> = 0x9000..0xF000;
    let mut ssid_buffer = [0; 32];
    let mut bssid_buffer = [0; 32];

     sequential_storage::map::store_item(
        &mut flash,
        NVS_FLASH_RANGE.clone(),
        &mut NoCache::new(),
        &mut ssid_buffer,
        &0,
        &ssid.as_bytes(),
    ).await.unwrap();
    sequential_storage::map::store_item(
        &mut flash,
        NVS_FLASH_RANGE.clone(),
        &mut NoCache::new(),
        &mut bssid_buffer,
        &1,
        &bssid.as_bytes(),
    ).await.unwrap();   
}

#[embassy_executor::task]
async fn sta_connection(mut controller: WifiController<'static>) {
    loop {
        match esp_wifi::wifi::wifi_state() {
            WifiState::StaConnected => {
                controller.wait_for_event(WifiEvent::StaDisconnected).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            log::info!("Starting wifi");
            controller.start_async().await.unwrap();
            log::info!("Wifi started!");

            log::info!("Scan");
            let scan_config = esp_wifi::wifi::ScanConfig::default();
            let result = controller
                .scan_with_config_async(scan_config)
                .await
                .unwrap();
            for ap in result {
                log::info!("{:?}", ap);
            }
        }
        log::info!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => log::info!("Wifi connected!"),
            Err(e) => {
                log::info!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

//this is the fn in the only AP example (https://github.com/esp-rs/esp-hal/blob/esp-hal-v1.0.0-rc.0/examples/src/bin/wifi_embassy_access_point.rs)
#[embassy_executor::task]
async fn ap_connection(mut controller: WifiController<'static>) {
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
            info!("Starting wifi");
            controller.start_async().await.unwrap();
            info!("Wifi started!");
        }
    }
}

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
fn extract_body(request: &str) -> Option<&str> {
    request.split("\r\n\r\n").nth(1)
}

fn parse_form(body: &str) -> Option<(String, String)> {
    let mut ssid = "";
    let mut bssid= "";
    let mut index = 0;
    for pair in body.split('&') {
        let mut iter = pair.splitn(2, '=');
        let _key = iter.next().unwrap_or("");
        let val = iter.next().unwrap_or("");
        if index == 0 {
            ssid = val;
        } else {
            bssid = val;
        }
        index += 1;
    }
    Some((ssid.to_string(), bssid.to_string()))
}

fn bytes_to_clean_string(data: &[u8]) -> Option<String> {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| start + pos)
        .unwrap_or(data.len());

    if start >= end {
        return None;
    }

    let slice = &data[start..end];
    core::str::from_utf8(slice).ok().map(String::from)
}
async fn send_ok(socket: &mut embassy_net::tcp::TcpSocket<'_>) -> bool {
    let body = "OK";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = socket.write_all(resp.as_bytes()).await;
    let _ = socket.flush().await;
    true
} 
