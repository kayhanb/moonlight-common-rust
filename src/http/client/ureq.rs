use std::{fmt, str::FromStr, sync::Arc};

use pem::Pem;
use rustls::{
    ClientConnection, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use thiserror::Error;
use tracing::{debug, instrument, trace};
use ureq::{
    Agent,
    config::Config,
    tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig, TlsProvider},
    unversioned::{
        resolver::DefaultResolver,
        transport::{
            Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, TcpConnector,
            Transport, TransportAdapter,
        },
    },
};

use crate::http::{
    ClientInfo, Endpoint, ParseError, TextResponse,
    client::{
        DEFAULT_LONG_TIMEOUT, DEFAULT_TIMEOUT, RequestError, blocking_client::RequestClient,
        hyperlike::build_url,
    },
};

/// Blocking request client built on [ureq].
///
/// Once a server certificate is known (after pairing) every HTTPS request is
/// **pinned** to it: the TLS handshake only succeeds when the server presents
/// exactly that leaf certificate (DER comparison). Host names are not checked —
/// GameStream hosts use self-signed certificates whose subject never matches
/// the address they are reached at — but the certificate itself must match.
/// Without a pinned certificate HTTPS falls back to ureq's regular verification,
/// which a self-signed host fails: there is no "trust anything" mode.
#[derive(Clone)]
pub struct UreqClient {
    config: Config,
    pinned: Option<Arc<CertificateDer<'static>>>,
}

impl fmt::Debug for UreqClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqClient")
            .field("pinned", &self.pinned.is_some())
            .finish()
    }
}

impl UreqClient {
    fn agent(&self) -> Agent {
        match &self.pinned {
            Some(pinned) => {
                let connector = ().chain(TcpConnector::default()).chain(PinnedTlsConnector {
                    pinned: Arc::clone(pinned),
                });
                Agent::with_parts(self.config.clone(), connector, DefaultResolver::default())
            }
            None => Agent::new_with_config(self.config.clone()),
        }
    }
}

#[derive(Debug, Error)]
pub enum UreqError {
    #[error("ureq: {0}")]
    Ureq(#[from] ureq::Error),
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    #[error("http: {0}")]
    Http(#[from] http::Error),
}

impl RequestError for UreqError {
    fn is_connect(&self) -> bool {
        matches!(
            self,
            Self::Ureq(ureq::Error::HostNotFound)
                | Self::Ureq(ureq::Error::ConnectionFailed)
                | Self::Ureq(ureq::Error::Io(_))
        )
    }
    fn is_encryption(&self) -> bool {
        matches!(self, Self::Ureq(ureq::Error::Tls(_)))
    }
}

impl TryInto<ParseError> for UreqError {
    type Error = Self;

    fn try_into(self) -> Result<ParseError, Self::Error> {
        match self {
            Self::Parse(err) => Ok(err),
            _ => Err(self),
        }
    }
}

impl RequestClient for UreqClient {
    type Error = UreqError;

    fn with_defaults() -> Result<Self, Self::Error> {
        let config = Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .build();

        Ok(Self {
            config,
            pinned: None,
        })
    }
    fn with_defaults_long_timeout() -> Result<Self, Self::Error> {
        let config = Agent::config_builder()
            .timeout_global(Some(DEFAULT_LONG_TIMEOUT))
            .build();

        Ok(Self {
            config,
            pinned: None,
        })
    }

    #[cfg_attr(
        not(feature = "__tracing_sensitive"),
        instrument(target = "moonlight::client::ureq", skip_all, err)
    )]
    #[cfg_attr(
        feature = "__tracing_sensitive",
        instrument(target = "moonlight::client::ureq", err)
    )]
    fn with_certificates(
        client_private_key: &Pem,
        client_certificate: &Pem,
        server_certificate: &Pem,
    ) -> Result<Self, Self::Error> {
        let client_certificate = Certificate::from_der(client_certificate.contents()).to_owned();
        let client_private_key = PrivateKey::from_pem(client_private_key.to_string().as_bytes())?;

        let server_certificate = Certificate::from_der(server_certificate.contents()).to_owned();
        let pinned = CertificateDer::from(server_certificate.der()).into_owned();

        // The client certificate and the pinned root are kept in the ureq
        // config so the connector can read them from `ConnectionDetails`;
        // verification itself is done by `PinnedTlsConnector`, not by ureq.
        let config = Agent::config_builder()
            .timeout_global(Some(DEFAULT_TIMEOUT))
            .tls_config(
                TlsConfig::builder()
                    .provider(TlsProvider::Rustls)
                    .client_cert(Some(ClientCert::new_with_certs(
                        &[client_certificate],
                        client_private_key,
                    )))
                    .root_certs(RootCerts::Specific(Arc::new(vec![server_certificate])))
                    .build(),
            )
            .build();

        Ok(Self {
            config,
            pinned: Some(Arc::new(pinned)),
        })
    }

    #[instrument(target = "moonlight::client::ureq", skip(self, request), fields(path = E::path()), err)]
    fn send_http<E>(
        &self,
        client_info: ClientInfo,
        hostport: &str,
        request: &E::Request,
    ) -> Result<E::Response, Self::Error>
    where
        E: Endpoint,
        E::Response: TextResponse<Err = ParseError>,
    {
        let url = build_url::<E, UreqError>(false, client_info, hostport, request)?;

        debug!(url = %url,"sending request");

        let response = self.agent().get(url).call()?;
        let response_text = response.into_body().read_to_string()?;

        debug!(response = ?response_text, "received response");

        let response = E::Response::from_str(&response_text)?;

        trace!(parsed_response = ?response, "parsed response");

        Ok(response)
    }

    #[instrument(target = "moonlight::client::ureq", skip(self, request), fields(path = E::path()), err)]
    fn send_https<E>(
        &self,
        client_info: ClientInfo,
        hostport: &str,
        request: &E::Request,
    ) -> Result<E::Response, Self::Error>
    where
        E: Endpoint,
        E::Response: TextResponse<Err = ParseError>,
    {
        let url = build_url::<E, UreqError>(true, client_info, hostport, request)?;

        debug!(url = %url,"sending request");

        let response = self.agent().get(url).call()?;
        let response_text = response.into_body().read_to_string()?;

        debug!(response = ?response_text, "received response");

        let response = E::Response::from_str(&response_text)?;

        trace!(parsed_response = ?response, "parsed response");

        Ok(response)
    }

    #[instrument(target = "moonlight::client::ureq", skip(self, request), fields(path = E::path()), err)]
    fn send_https_with_bytes<E>(
        &self,
        client_info: ClientInfo,
        hostport: &str,
        request: &E::Request,
    ) -> Result<E::Response, Self::Error>
    where
        E: Endpoint<Response = Vec<u8>>,
    {
        let url = build_url::<E, UreqError>(true, client_info, hostport, request)?;

        debug!(url = %url,"sending request");

        let response = self.agent().get(url).call()?;
        let response_bytes = response.into_body().read_to_vec()?;

        Ok(response_bytes)
    }
}

/// TLS wrapper that accepts exactly one server certificate.
///
/// Mirrors ureq's own `RustlsConnector` (TCP transport wrapped in a rustls
/// `StreamOwned`) but builds the rustls config here so a custom
/// [`ServerCertVerifier`] can be installed: ureq's public TLS config offers
/// either full WebPKI verification (impossible for self-signed GameStream
/// hosts reached by address) or none at all.
struct PinnedTlsConnector {
    pinned: Arc<CertificateDer<'static>>,
}

impl fmt::Debug for PinnedTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTlsConnector").finish()
    }
}

impl<In: Transport> Connector<In> for PinnedTlsConnector {
    type Out = Either<In, PinnedTlsTransport>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            panic!("PinnedTlsConnector requires a chained transport");
        };

        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }

        let config = self.rustls_config(details.config.tls_config())?;

        // The name only feeds SNI and is never verified; an IP literal is fine.
        let name: ServerName<'static> = details
            .uri
            .authority()
            .map(|authority| authority.host())
            .unwrap_or_default()
            .trim_matches(|c| c == '[' || c == ']')
            .to_string()
            .try_into()
            .map_err(|_| ureq::Error::Tls("Rustls invalid dns name error"))?;

        let conn = ClientConnection::new(config, name)
            .map_err(|_| ureq::Error::Tls("Rustls client connection error"))?;
        let mut sock = TransportAdapter::new(transport.boxed());
        sock.set_timeout(details.timeout);
        let mut stream = StreamOwned { conn, sock };
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|_| ureq::Error::Tls("Rustls handshake error"))?;

        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );

        Ok(Some(Either::B(PinnedTlsTransport { buffers, stream })))
    }
}

impl PinnedTlsConnector {
    fn rustls_config(&self, tls: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, ureq::Error> {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

        let verifier = PinnedVerifier {
            pinned: Arc::clone(&self.pinned),
            algorithms: provider.signature_verification_algorithms,
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(rustls::ALL_VERSIONS)
            .map_err(|_| ureq::Error::Tls("Rustls protocol versions error"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));

        let mut config = match tls.client_cert() {
            Some(client) => {
                let chain = client
                    .certs()
                    .iter()
                    .map(|c| CertificateDer::from(c.der()).into_owned())
                    .collect();
                let key = PrivateKeyDer::try_from(client.private_key().der().to_vec())
                    .map_err(|_| ureq::Error::Tls("Rustls invalid client key"))?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|_| ureq::Error::Tls("Rustls invalid client certificate"))?
            }
            None => builder.with_no_client_auth(),
        };
        config.enable_sni = tls.use_sni();
        // GameStream hosts (Sunshine) cannot resume sessions.
        config.resumption = rustls::client::Resumption::disabled();

        Ok(Arc::new(config))
    }
}

/// Verifier for a certificate that was exchanged during pairing: the leaf must
/// be byte-for-byte the pinned one. Nothing else about the chain matters (it
/// is self-signed), and the host name is not checked. Signatures made during
/// the handshake are still verified against that certificate's key, so a peer
/// merely *presenting* the certificate without holding its private key fails.
#[derive(Debug)]
struct PinnedVerifier {
    pinned: Arc<CertificateDer<'static>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref().as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

pub struct PinnedTlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl fmt::Debug for PinnedTlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTlsTransport").finish()
    }
}

impl Transport for PinnedTlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        use std::io::Write;
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        use std::io::Read;
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}
