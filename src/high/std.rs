use std::{
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    sync::{Mutex, PoisonError, RwLock},
};

use uuid::Uuid;

use crate::{
    App, AppId, ServerState, ServerVersion,
    high::{MoonlightClientError, SessionStart},
    http::{
        ClientIdentifier, ClientInfo, ClientSecret, DEFAULT_UNIQUE_ID, ServerIdentifier,
        app_list::{AppListEndpoint, AppListRequest, AppListResponse},
        box_art::{AppBoxArtEndpoint, AppBoxArtRequest},
        cancel::{CancelEndpoint, CancelRequest},
        client::blocking_client::RequestClient,
        launch::{ClientStreamRequest, LaunchEndpoint},
        pair::{
            PairEndpoint, PairPin, PairingCryptoBackend,
            client::{ClientPairing, ClientPairingError, ClientPairingOutput},
        },
        resume::ResumeEndpoint,
        server_info::{
            ApolloPermissions, ServerInfoEndpoint, ServerInfoRequest, ServerInfoResponse,
        },
        unpair::{UnpairEndpoint, UnpairRequest},
    },
    mac::MacAddress,
    stream::{
        AesIv, AesKey, MoonlightStreamConfig, MoonlightStreamSettings, SunshineEncryption,
        video::ServerCodecModeSupport,
    },
};

fn poison_err<T>(_err: PoisonError<T>) -> MoonlightClientError {
    MoonlightClientError::Poisoned(PoisonError::new(()))
}

pub fn broadcast_magic_packet(mac: MacAddress) -> Result<(), io::Error> {
    let mut magic_packet = [0u8; 6 * 17];

    magic_packet[0..6].copy_from_slice(&[255, 255, 255, 255, 255, 255]);
    for i in 1..17 {
        magic_packet[(i * 6)..((i + 1) * 6)].copy_from_slice(&mac.to_bytes());
    }

    let broadcast = SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 9);

    let socket = UdpSocket::bind("0.0.0.0:0")?;

    socket.set_broadcast(true)?;
    socket.send_to(&magic_packet, broadcast)?;

    Ok(())
}

pub struct MoonlightHost<Client> {
    client_unique_id: String,
    client: Mutex<Client>,
    address: String,
    http_port: u16,
    cache: RwLock<Cache>,
}

#[derive(Debug, Default)]
struct Cache {
    authenticated: Option<Authenticated>,
    server_info: Option<ServerInfoResponse>,
    app_list: Option<AppListResponse>,
}

#[derive(Debug)]
struct Authenticated {
    client_identifier: ClientIdentifier,
    client_secret: ClientSecret,
    server_identifier: ServerIdentifier,
}

fn req_err<Err>(err: Err) -> MoonlightClientError
where
    Err: Error + Send + Sync + 'static,
{
    MoonlightClientError::Backend(Box::new(err))
}
fn crypto_err<Err>(err: ClientPairingError<Err>) -> MoonlightClientError
where
    Err: Error + Send + Sync + 'static,
{
    MoonlightClientError::Pairing(ClientPairingError::from_err(err))
}

/// TODO: some docs
impl<Client> MoonlightHost<Client>
where
    Client: RequestClient,
    <Client as RequestClient>::Error: Error + Send + Sync + 'static,
{
    pub fn new(
        address: String,
        http_port: u16,
        unique_id: Option<String>,
    ) -> Result<Self, MoonlightClientError> {
        Ok(Self {
            client: Mutex::new(Client::with_defaults().map_err(req_err)?),
            client_unique_id: unique_id.unwrap_or_else(|| DEFAULT_UNIQUE_ID.to_string()),
            address,
            http_port,
            cache: Default::default(),
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    pub fn http_address(&self) -> String {
        format!("{}:{}", self.address, self.http_port)
    }

    pub fn update(self: &MoonlightHost<Client>) -> Result<(), MoonlightClientError> {
        let mut cache_lock = self.cache.write().map_err(poison_err)?;
        let client = self.client.lock().map_err(poison_err)?;

        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        let http_address = self.http_address();
        let server_info = client
            .send_http::<ServerInfoEndpoint>(
                client_info.clone(),
                &http_address,
                &ServerInfoRequest {},
            )
            .map_err(req_err)?;

        let https_port = server_info.https_port;
        cache_lock.server_info = Some(server_info);

        if cache_lock.authenticated.is_some() {
            let https_address = Self::build_https_address(&self.address, https_port);

            let server_info_secure = client
                .send_https::<ServerInfoEndpoint>(
                    client_info.clone(),
                    &https_address,
                    &ServerInfoRequest {},
                )
                .map_err(req_err)?;

            cache_lock.server_info = Some(server_info_secure);

            let app_list = client
                .send_https::<AppListEndpoint>(
                    client_info.clone(),
                    &https_address,
                    &AppListRequest {},
                )
                .map_err(req_err)?;

            cache_lock.app_list = Some(app_list);
        } else {
            cache_lock.app_list = None;
        }

        drop(cache_lock);
        drop(client);

        Ok(())
    }

    fn server_info<R>(
        &self,
        f: impl FnOnce(&ServerInfoResponse) -> R,
    ) -> Result<R, MoonlightClientError> {
        let cache = self.cache.read().map_err(poison_err)?;

        if let Some(server_info) = &cache.server_info {
            Ok(f(server_info))
        } else {
            drop(cache);

            self.update()?;
            let response = self.cache.read().map_err(poison_err)?;
            let Some(server_info) = &response.server_info else {
                unreachable!()
            };

            Ok(f(server_info))
        }
    }

    pub fn https_port(&self) -> Result<u16, MoonlightClientError> {
        self.server_info(|info| info.https_port)
    }

    fn build_https_address(address: &str, https_port: u16) -> String {
        format!("{address}:{https_port}")
    }
    pub fn https_address(&self) -> Result<String, MoonlightClientError> {
        let https_port = self.https_port()?;
        Ok(Self::build_https_address(&self.address, https_port))
    }
    pub fn external_port(&self) -> Result<Option<u16>, MoonlightClientError> {
        self.server_info(|info| info.external_port)
    }

    pub fn host_name(&self) -> Result<String, MoonlightClientError> {
        self.server_info(|info| info.host_name.clone())
    }
    pub fn version(&self) -> Result<ServerVersion, MoonlightClientError> {
        self.server_info(|info| info.app_version)
    }

    pub fn gfe_version(&self) -> Result<String, MoonlightClientError> {
        self.server_info(|info| info.gfe_version.clone())
    }
    pub fn unique_id(&self) -> Result<Uuid, MoonlightClientError> {
        self.server_info(|info| info.unique_id)
    }

    /// Returns None if unpaired
    pub fn mac(&self) -> Result<Option<MacAddress>, MoonlightClientError> {
        self.server_info(|info| info.mac)
    }
    pub fn local_ip(&self) -> Result<Ipv4Addr, MoonlightClientError> {
        self.server_info(|info| info.local_ip)
    }

    pub fn current_game(&self) -> Result<u32, MoonlightClientError> {
        self.server_info(|info| info.current_game)
    }

    pub fn state(&self) -> Result<ServerState, MoonlightClientError> {
        self.server_info(|info| info.state)
    }

    pub fn max_luma_pixels_hevc(&self) -> Result<u32, MoonlightClientError> {
        self.server_info(|info| info.max_luma_pixels_hevc)
    }

    pub fn server_codec_mode_support(
        &self,
    ) -> Result<ServerCodecModeSupport, MoonlightClientError> {
        self.server_info(|info| info.server_codec_mode_support)
    }

    pub fn set_identity(
        &self,
        client_identifier: ClientIdentifier,
        client_secret: ClientSecret,
        server_identifier: ServerIdentifier,
    ) -> Result<(), MoonlightClientError> {
        let client = Client::with_certificates(
            &client_secret.to_pem(),
            &client_identifier.to_pem(),
            &server_identifier.to_pem(),
        )
        .map_err(req_err)?;

        {
            let mut client_lock = self.client.lock().map_err(poison_err)?;
            *client_lock = client;

            let mut cache = self.cache.write().map_err(poison_err)?;

            cache.authenticated = Some(Authenticated {
                client_identifier,
                client_secret,
                server_identifier,
            });

            drop(client_lock);
        }

        self.update()?;

        Ok(())
    }
    pub fn identity(&self) -> Option<(ClientIdentifier, ClientSecret, ServerIdentifier)> {
        let cache = self.cache.read().ok()?;

        cache.authenticated.as_ref().map(|authenticated| {
            (
                authenticated.client_identifier.clone(),
                authenticated.client_secret.clone(),
                authenticated.server_identifier.clone(),
            )
        })
    }

    pub fn is_paired(&self) -> Result<bool, MoonlightClientError> {
        let cache = self.cache.read().map_err(poison_err)?;
        Ok(cache.authenticated.is_some())
    }
    fn check_paired(&self) -> Result<(), MoonlightClientError> {
        if self.is_paired()? {
            Ok(())
        } else {
            Err(MoonlightClientError::Unauthenticated)
        }
    }

    pub fn pair<Crypto>(
        &self,
        client_identifier: &ClientIdentifier,
        client_secret: &ClientSecret,
        device_name: String,
        pin: PairPin,
        crypto_provider: Crypto,
    ) -> Result<(), MoonlightClientError>
    where
        Crypto: PairingCryptoBackend,
        Crypto::Error: Error + Send + Sync + 'static,
    {
        let http_address = self.http_address();
        let server_version = self.version()?;
        let https_address = self.https_address()?;

        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        let mut client = Client::with_defaults_long_timeout().map_err(req_err)?;

        let mut pairing = ClientPairing::new(
            client_identifier.clone(),
            client_secret.clone(),
            server_version,
            device_name,
            pin,
            crypto_provider,
        )
        .map_err(crypto_err)?;

        match self.pair_impl(
            &http_address,
            &https_address,
            client_identifier,
            client_secret,
            client_info.clone(),
            &mut pairing,
            &mut client,
        ) {
            Ok(()) => {}
            Err(err) => {
                // Try to unpair
                let _ = client.send_http::<UnpairEndpoint>(
                    client_info,
                    &http_address,
                    &UnpairRequest {},
                );

                return Err(err);
            }
        }

        // Replace client
        {
            let mut client_lock = self.client.lock().map_err(poison_err)?;
            *client_lock = client;
        }

        // Update our info
        self.update().map_err(req_err)?;

        Ok(())
    }
    fn pair_impl<Crypto>(
        &self,
        http_address: &str,
        https_address: &str,
        client_identifier: &ClientIdentifier,
        client_secret: &ClientSecret,
        client_info: ClientInfo,
        pairing: &mut ClientPairing<Crypto>,
        client: &mut Client,
    ) -> Result<(), MoonlightClientError>
    where
        Crypto: PairingCryptoBackend,
        Crypto::Error: Error + Send + Sync + 'static,
    {
        let mut server_identifier = None;

        loop {
            match pairing.poll_output().map_err(crypto_err)? {
                ClientPairingOutput::SendHttpPairRequest(request) => {
                    let response = client
                        .send_http::<PairEndpoint>(client_info.clone(), http_address, &request)
                        .map_err(req_err)?;

                    pairing.handle_response(response).map_err(crypto_err)?;
                }
                ClientPairingOutput::SetServerIdentifier(new_server_identifier) => {
                    *client = Client::with_certificates(
                        &client_secret.to_pem(),
                        &client_identifier.to_pem(),
                        &new_server_identifier.to_pem(),
                    )
                    .map_err(req_err)?;

                    server_identifier = Some(new_server_identifier);
                }
                ClientPairingOutput::SendHttpsPairRequest(request) => {
                    assert!(
                        server_identifier.is_some(),
                        "ClientPairing didn't set ServerIdentifier but tried to make a https request"
                    );

                    let response = client
                        .send_https::<PairEndpoint>(client_info.clone(), https_address, &request)
                        .map_err(req_err)?;

                    pairing.handle_response(response).map_err(crypto_err)?;
                }
                ClientPairingOutput::Success => {
                    {
                        let mut cache_lock = self.cache.write().map_err(poison_err)?;
                        cache_lock.authenticated = Some(Authenticated {
                            client_identifier: client_identifier.clone(),
                            client_secret: client_secret.clone(),
                            server_identifier: server_identifier
                                .take()
                                .expect("PairingClient didn't set a server identifier"),
                        });
                    }

                    return Ok(());
                }
            };
        }
    }

    pub fn unpair(&self) -> Result<(), MoonlightClientError> {
        self.check_paired()?;

        let https_address = self.https_address()?;
        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        {
            let mut client = self.client.lock().map_err(poison_err)?;

            client
                .send_https::<UnpairEndpoint>(client_info, &https_address, &UnpairRequest {})
                .map_err(req_err)?;

            let new_client = Client::with_defaults().map_err(req_err)?;
            *client = new_client;
        }

        Ok(())
    }

    pub fn apollo_permissions(&self) -> Result<Option<ApolloPermissions>, MoonlightClientError> {
        self.check_paired()?;

        self.server_info(|info| info.apollo_permissions.clone())
    }

    pub fn app_list(&self) -> Result<Vec<App>, MoonlightClientError> {
        let cache = self.cache.read().map_err(poison_err)?;

        if cache.authenticated.is_none() {
            return Err(MoonlightClientError::Unauthenticated);
        }

        if let Some(app_list) = &cache.app_list {
            Ok(app_list.apps.clone())
        } else {
            drop(cache);

            self.update()?;
            let cache = self.cache.read().map_err(poison_err)?;
            let Some(app_list) = &cache.app_list else {
                unreachable!()
            };

            Ok(app_list.apps.clone())
        }
    }

    pub fn request_app_image(&self, app_id: AppId) -> Result<Vec<u8>, MoonlightClientError> {
        self.check_paired()?;

        let https_address = self.https_address()?;

        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        let client = { self.client.lock().map_err(poison_err)?.clone() };
        let response = client
            .send_https_with_bytes::<AppBoxArtEndpoint>(
                client_info,
                &https_address,
                &AppBoxArtRequest {
                    app_id,
                    asset_type: 2,
                    asset_idx: 0,
                },
            )
            .map_err(req_err)?;

        Ok(response)
    }

    /// Starts a stream.
    /// The returned [MoonlightStreamConfig] must be passed into a stream implementation.
    ///
    /// Before starting the stream you should adjust the settings using [MoonlightStreamSettings::adjust_for_server].
    pub fn start_stream(
        &self,
        app_id: AppId,
        settings: &MoonlightStreamSettings,
        aes_key: AesKey,
        aes_iv: AesIv,
        launch_query_parameters: &str,
    ) -> Result<MoonlightStreamConfig, MoonlightClientError> {
        // Clearing cache so we refresh and can see if there's a game -> launch or resume?
        self.update()?;

        self.start_stream_cached(
            app_id,
            settings,
            aes_key,
            aes_iv,
            launch_query_parameters,
            SessionStart::FromCache,
        )
    }

    /// Starts a stream without refreshing the host state first.
    ///
    /// [Self::start_stream] refreshes the server info and the app list before
    /// it opens the session, only to learn whether an app is already running
    /// (launch or resume). Every request runs on a new connection, so on a
    /// distant host that refresh costs more than the session request itself.
    /// This variant trusts what is cached:
    ///
    /// - [SessionStart::FromCache] decides from the cached server info. Use it
    ///   right after [Self::update] or [Self::set_identity] fetched it.
    /// - [SessionStart::Resume] always resumes. Use it to reconnect to a host
    ///   whose session this client left open: the resume request is the only
    ///   one sent.
    ///
    /// A host that answers a resume with `resume = 0` is reported as
    /// [MoonlightClientError::ResumeRefused]; refresh with
    /// [Self::start_stream] and try again.
    pub fn start_stream_cached(
        &self,
        app_id: AppId,
        settings: &MoonlightStreamSettings,
        aes_key: AesKey,
        aes_iv: AesIv,
        launch_query_parameters: &str,
        start: SessionStart,
    ) -> Result<MoonlightStreamConfig, MoonlightClientError> {
        let address = self.address.clone();
        let https_address = self.https_address()?;

        let resume = match start {
            SessionStart::Resume => true,
            SessionStart::FromCache => self.current_game()? != 0,
        };

        let request = ClientStreamRequest {
            app_id,
            mode_width: settings.width,
            mode_height: settings.height,
            mode_fps: settings.fps,
            hdr: settings.hdr,
            sops: settings.sops,
            surround_audio_info: settings.audio_config,
            local_audio_play_mode: settings.local_audio_play_mode,
            gamepads_attached_mask: settings.gamepads_attached.bits() as i32,
            gamepads_persist_after_disconnect: settings.gamepads_persist_after_disconnect,
            ri_key: aes_key,
            ri_key_id: aes_iv,
            core_version: None,
            additional_query_parameters: launch_query_parameters.to_string(),
        };

        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        let rtsp_session_url = {
            let client = self.client.lock().map_err(poison_err)?;

            if !resume {
                let launch_response = client
                    .send_https::<LaunchEndpoint>(client_info, &https_address, &request)
                    .map_err(req_err)?;

                launch_response.rtsp_session_url
            } else {
                let resume_response = client
                    .send_https::<ResumeEndpoint>(client_info, &https_address, &request)
                    .map_err(req_err)?;

                // The resume response is parsed without its status code, so a
                // refusal ("no running app", "failed to initialize video
                // capture") only shows up here. Without a session the
                // connection would fail later with an unexplained error.
                if resume_response.resume == 0 {
                    return Err(MoonlightClientError::ResumeRefused);
                }

                resume_response.rtsp_session_url
            }
        };

        let app_version = self.version()?;
        let server_codec_mode_support = self.server_codec_mode_support()?;
        let gfe_version = self.gfe_version()?.to_owned();
        let apollo_permissions = self.apollo_permissions()?;
        let foundation_enable_mic = settings.enable_mic && app_version.is_foundation();

        Ok(MoonlightStreamConfig {
            address,
            gfe_version: Some(gfe_version),
            server_codec_mode_support,
            rtsp_session_url,
            encryption: SunshineEncryption { aes_key, aes_iv },
            version: app_version,
            apollo_permissions,
            foundation_enable_mic,
        })
    }

    pub fn cancel(&mut self) -> Result<bool, MoonlightClientError> {
        self.check_paired()?;

        let https_hostport = self.https_address()?;

        let client_info = ClientInfo {
            unique_id: self.client_unique_id.clone(),
            uuid: Uuid::new_v4(),
        };

        let response = {
            let client = self.client.lock().map_err(poison_err)?;

            client
                .send_https::<CancelEndpoint>(client_info, &https_hostport, &CancelRequest {})
                .map_err(req_err)?
        };

        if !response.cancelled {
            return Ok(false);
        }

        self.update()?;

        let current_game = self.current_game()?;
        if current_game != 0 {
            // We're not the device that opened this session
            return Ok(false);
        }

        Ok(response.cancelled)
    }
}

#[cfg(test)]
mod tests {
    use ::std::{cell::RefCell, str::FromStr};

    use pem::Pem;
    use thiserror::Error;

    use super::*;
    use crate::{
        http::{Endpoint, ParseError, TextResponse, client::RequestError},
        stream::{
            EncryptionFlags, StreamingConfig,
            audio::AudioConfig,
            control::ActiveGamepads,
            video::{ColorRange, ColorSpace, VideoFormats},
        },
    };

    const DESKTOP: AppId = AppId(881448767);
    const SESSION_URL: &str = "rtspenc://192.168.178.140:48010";

    /// What the fake host is doing; a test changes it between calls.
    #[derive(Clone, Copy)]
    struct FakeHost {
        /// `currentgame` in the server info: 0 when no app is running.
        current_game: u32,
        /// `resume` in the resume response: 0 when the host refuses.
        resume: u32,
    }

    thread_local! {
        static HOST: RefCell<FakeHost> = const {
            RefCell::new(FakeHost {
                current_game: 0,
                resume: 1,
            })
        };
        /// Every request the fake host received, in order.
        static SEEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    #[derive(Debug, Error)]
    enum FakeError {
        #[error("parse: {0}")]
        Parse(#[from] ParseError),
    }

    impl RequestError for FakeError {
        fn is_connect(&self) -> bool {
            false
        }
        fn is_encryption(&self) -> bool {
            false
        }
    }

    impl TryInto<ParseError> for FakeError {
        type Error = Self;

        fn try_into(self) -> Result<ParseError, Self::Error> {
            match self {
                Self::Parse(err) => Ok(err),
            }
        }
    }

    /// Answers like a Sunshine host and records the request.
    fn answer<E>(scheme: &str) -> Result<E::Response, FakeError>
    where
        E: Endpoint,
        E::Response: TextResponse<Err = ParseError>,
    {
        SEEN.with(|seen| seen.borrow_mut().push(format!("{scheme} {}", E::path())));
        let host = HOST.with(|host| *host.borrow());

        let body = match E::path() {
            "/serverinfo" => format!(
                "<root status_code=\"200\">\
                 <hostname>PCNAME</hostname>\
                 <appversion>7.1.431.-1</appversion>\
                 <GfeVersion>3.23.0.74</GfeVersion>\
                 <uniqueid>45924F0E-6465-B60F-B517-95DC63714036</uniqueid>\
                 <HttpsPort>47984</HttpsPort>\
                 <ExternalPort>47989</ExternalPort>\
                 <MaxLumaPixelsHEVC>0</MaxLumaPixelsHEVC>\
                 <mac>00:B0:D0:63:C2:26</mac>\
                 <LocalIP>192.168.178.140</LocalIP>\
                 <ServerCodecModeSupport>262145</ServerCodecModeSupport>\
                 <PairStatus>1</PairStatus>\
                 <currentgame>{}</currentgame>\
                 <state>{}</state>\
                 </root>",
                host.current_game,
                if host.current_game == 0 {
                    "SUNSHINE_SERVER_FREE"
                } else {
                    "SUNSHINE_SERVER_BUSY"
                },
            ),
            "/applist" => "<root status_code=\"200\">\
                 <App>\
                 <IsHdrSupported>0</IsHdrSupported>\
                 <AppTitle>Desktop</AppTitle>\
                 <ID>881448767</ID>\
                 </App>\
                 </root>"
                .to_string(),
            "/launch" => format!(
                "<root status_code=\"200\">\
                 <gamesession>1</gamesession>\
                 <sessionUrl0>{SESSION_URL}</sessionUrl0>\
                 </root>"
            ),
            "/resume" if host.resume == 0 => {
                "<root status_code=\"503\" status_message=\"No running app to resume\">\
                 <resume>0</resume>\
                 </root>"
                    .to_string()
            }
            "/resume" => format!(
                "<root status_code=\"200\">\
                 <resume>{}</resume>\
                 <sessionUrl0>{SESSION_URL}</sessionUrl0>\
                 </root>",
                host.resume
            ),
            other => panic!("unexpected request: {other}"),
        };

        Ok(E::Response::from_str(&body)?)
    }

    #[derive(Clone)]
    struct FakeClient;

    impl RequestClient for FakeClient {
        type Error = FakeError;

        fn with_defaults() -> Result<Self, Self::Error> {
            Ok(Self)
        }
        fn with_defaults_long_timeout() -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn with_certificates(
            _client_private_key: &Pem,
            _client_certificate: &Pem,
            _server_certificate: &Pem,
        ) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn send_http<E>(
            &self,
            _client_info: ClientInfo,
            _hostport: &str,
            _request: &E::Request,
        ) -> Result<E::Response, Self::Error>
        where
            E: Endpoint,
            E::Response: TextResponse<Err = ParseError>,
        {
            answer::<E>("http")
        }

        fn send_https<E>(
            &self,
            _client_info: ClientInfo,
            _hostport: &str,
            _request: &E::Request,
        ) -> Result<E::Response, Self::Error>
        where
            E: Endpoint,
            E::Response: TextResponse<Err = ParseError>,
        {
            answer::<E>("https")
        }

        fn send_https_with_bytes<E>(
            &self,
            _client_info: ClientInfo,
            _hostport: &str,
            _request: &E::Request,
        ) -> Result<E::Response, Self::Error>
        where
            E: Endpoint<Response = Vec<u8>>,
        {
            unreachable!("these tests request no box art")
        }
    }

    /// A paired host whose state was just read, as right after `set_identity`.
    fn paired_host(current_game: u32) -> MoonlightHost<FakeClient> {
        HOST.with(|host| {
            *host.borrow_mut() = FakeHost {
                current_game,
                resume: 1,
            }
        });

        let host = MoonlightHost::<FakeClient>::new("192.168.178.140".to_string(), 47989, None)
            .expect("host");
        let pem = || Pem::new("CERTIFICATE", vec![1, 2, 3]);
        host.set_identity(
            ClientIdentifier::from_pem(pem()),
            ClientSecret::from_pem(pem()),
            ServerIdentifier::from_pem(pem()),
        )
        .expect("identity");

        SEEN.with(|seen| seen.borrow_mut().clear());
        host
    }

    /// The requests sent since the last call.
    fn seen() -> Vec<String> {
        SEEN.with(|seen| ::std::mem::take(&mut *seen.borrow_mut()))
    }

    fn settings() -> MoonlightStreamSettings {
        MoonlightStreamSettings {
            width: 1920,
            height: 1080,
            fps: 60,
            fps_x100: 6000,
            bitrate: 20_000,
            packet_size: 1024,
            encryption_flags: EncryptionFlags::all(),
            streaming_remotely: StreamingConfig::Auto,
            sops: true,
            hdr: false,
            supported_video_formats: VideoFormats::H264,
            color_space: ColorSpace::Rec709,
            color_range: ColorRange::Limited,
            local_audio_play_mode: false,
            audio_config: AudioConfig::STEREO,
            gamepads_attached: ActiveGamepads::empty(),
            gamepads_persist_after_disconnect: false,
            enable_mic: false,
        }
    }

    /// `None` refreshes first ([MoonlightHost::start_stream]).
    fn start(
        host: &MoonlightHost<FakeClient>,
        cached: Option<SessionStart>,
    ) -> Result<MoonlightStreamConfig, MoonlightClientError> {
        let (key, iv) = (AesKey([7; 16]), AesIv(7));
        match cached {
            None => host.start_stream(DESKTOP, &settings(), key, iv, ""),
            Some(start) => host.start_stream_cached(DESKTOP, &settings(), key, iv, "", start),
        }
    }

    #[test]
    fn start_stream_refreshes_the_host_state_first() {
        let host = paired_host(0);
        // An app was started on the host after its state was read.
        HOST.with(|host| host.borrow_mut().current_game = DESKTOP.0);

        start(&host, None).expect("stream config");

        assert_eq!(
            seen(),
            [
                "http /serverinfo",
                "https /serverinfo",
                "https /applist",
                "https /resume"
            ]
        );
    }

    #[test]
    fn cached_start_sends_only_the_session_request() {
        let host = paired_host(0);
        let config = start(&host, Some(SessionStart::FromCache)).expect("stream config");
        assert_eq!(seen(), ["https /launch"]);
        assert_eq!(config.rtsp_session_url.as_deref(), Some(SESSION_URL));

        let host = paired_host(DESKTOP.0);
        let config = start(&host, Some(SessionStart::FromCache)).expect("stream config");
        assert_eq!(seen(), ["https /resume"]);
        assert_eq!(config.rtsp_session_url.as_deref(), Some(SESSION_URL));
    }

    #[test]
    fn forced_resume_ignores_the_cached_state() {
        // The state was cached before this client launched its session.
        let host = paired_host(0);

        start(&host, Some(SessionStart::Resume)).expect("stream config");

        assert_eq!(seen(), ["https /resume"]);
    }

    #[test]
    fn refused_resume_is_an_error() {
        let host = paired_host(DESKTOP.0);
        HOST.with(|host| host.borrow_mut().resume = 0);

        let err = start(&host, Some(SessionStart::Resume)).expect_err("refusal");

        assert!(matches!(err, MoonlightClientError::ResumeRefused), "{err}");
        assert_eq!(seen(), ["https /resume"]);
    }
}
