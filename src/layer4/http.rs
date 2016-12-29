//! Hypertext Transfer Protocol related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The HTTP parser
pub struct HttpParser;

impl Parser for HttpParser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse a `HttpPacket` from an `&[u8]`
    fn parse<'a>(&self,
                 input: &'a [u8],
                 _: Option<&ParserNode>,
                 _: Option<&ProtocolGraph>,
                 result: Option<&Vec<Self::Result>>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,

            // Check the transport protocol from the parent parser (TCP or TLS)
            result: alt!(
                // TCP based plain text transfer
                cond_reduce!(match result {
                    Some(vector) => match vector.last() {
                        Some(&Layer::Tcp(_)) => true,
                        _ => false, // Previous result found, but not correct parent
                    },
                    None => true, // Parse also if no result is given, for testability
                }, HttpPacket::parse_plain) |

                // TLS based encrypted traffic
                apply!(HttpPacket::parse_encrypted, result)
            ) >>

            (result)
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Http(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a Hypertext Transfer Protocol packet
pub enum HttpPacket {
    /// Specifies a HTTP request
    Request(HttpRequest),

    /// Specifies a HTTP response
    Response(HttpResponse),

    /// Could be a plain or encrypted HTTP packet, but there is no further data parsable
    Any,
}

impl HttpPacket {
    named!(parse_plain<&[u8], Layer>,
           alt!(call!(HttpRequest::parse) | call!(HttpResponse::parse))
    );

    fn parse_encrypted<'a>(input: &'a [u8], result: Option<&Vec<Layer>>) -> IResult<&'a [u8], Layer> {
        expr_opt!(input,
            match result {
                Some(vector) => match vector.last() {
                    Some(&Layer::Tls(_)) => {
                        if let Some(transport_layer) = vector.iter().rev().nth(1) {
                            match transport_layer {
                                &Layer::Tcp(ref data) if (data.source_port == 443 || data.dest_port == 443) => {
                                    Some(Layer::Http(HttpPacket::Any))
                                }
                                _ => None
                            }
                        } else {
                            None // No transport layer available
                        }
                    },
                    _ => None, // Previous result found, but not correct parent
                },
                _ => None,
            }
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
/// A HTTP request representation
pub struct HttpRequest {
    /// The HTTP request method
    pub request_method: HttpRequestMethod,

    /// The HTTP version
    pub version: HttpVersion,

    /// The HTTP path to be accessed
    pub path: String,

    /// Available HTTP headers
    pub headers: Vec<HttpHeader>,
}

impl HttpRequest {
    named!(parse<&[u8], Layer>,
        ws!(do_parse!(
            // HTTP Request parsing
            method: alt!(
                map!(tag_fast!("GET"), |_| HttpRequestMethod::Get) |
                map!(tag_fast!("POST"), |_| HttpRequestMethod::Post) |
                map!(tag_fast!("HEAD"), |_| HttpRequestMethod::Head) |
                map!(tag_fast!("PUT"), |_| HttpRequestMethod::Put) |
                map!(tag_fast!("DELETE"), |_| HttpRequestMethod::Delete) |
                map!(tag_fast!("TRACE"), |_| HttpRequestMethod::Trace) |
                map!(tag_fast!("OPTIONS"), |_| HttpRequestMethod::Options) |
                map!(tag_fast!("CONNECT"), |_| HttpRequestMethod::Connect) |
                map!(tag_fast!("PATCH"), |_| HttpRequestMethod::Patch)
            ) >>

            path: map_res!(take_until!(" "), str::from_utf8) >>
            tag_fast!("HTTP/") >>
            version: call!(HttpVersion::parse) >>
            headers: call!(HttpHeader::parse) >>

            (Layer::Http(HttpPacket::Request(HttpRequest {
                request_method: method,
                path: path.to_owned(),
                version: version,
                headers: headers,
            })))
        ))
    );
}

#[derive(Debug, Eq, PartialEq)]
/// List of supported HTTP request methods
pub enum HttpRequestMethod {
    /// The GET method requests a representation of the specified resource.
    Get,

    /// The POST method requests that the server accept the entity enclosed in the request as a new
    /// subordinate of the web resource identified by the URI.
    Post,

    /// The HEAD method asks for a response identical to that of a GET request, but without the
    /// response body.
    Head,

    /// The PUT method requests that the enclosed entity be stored under the supplied URI.
    Put,

    /// The DELETE method deletes the specified resource.
    Delete,

    /// The TRACE method echoes the received request so that a client can see what (if any) changes
    /// or additions have been made by intermediate servers.
    Trace,

    /// The OPTIONS method returns the HTTP methods that the server supports for the specified URL.
    Options,

    /// The CONNECT method converts the request connection to a transparent TCP/IP tunnel, usually
    /// to facilitate SSL-encrypted communication (HTTPS) through an unencrypted HTTP proxy.
    Connect,

    /// The PATCH method applies partial modifications to a resource.
    Patch,
}

#[derive(Debug, Eq, PartialEq)]
/// HTTP protocol version
pub struct HttpVersion {
    /// Major part of the HTTP version
    pub major: u8,

    /// Minor part of the HTTP version
    pub minor: u8,
}

impl HttpVersion {
    named!(parse<&[u8], HttpVersion>,
        do_parse!(
            tuple: separated_pair!(map_res!(map_res!(digit, str::from_utf8), FromStr::from_str),
                                   tag_fast!("."),
                                   map_res!(map_res!(digit, str::from_utf8), FromStr::from_str)) >>
            (HttpVersion {
                major: tuple.0,
                minor: tuple.1,
            })
        )
    );
}

#[derive(Debug, Eq, PartialEq)]
/// A generic HTTP header field
pub struct HttpHeader {
    /// A Key, like "Host"
    pub key: String,

    /// A value, like "www.domain.com"
    pub value: String,
}

impl HttpHeader {
    fn from_tuple(tuple: (&str, &str)) -> Self {
        HttpHeader {
            key: tuple.0.to_owned(),
            value: tuple.1.to_owned(),
        }
    }

    named!(parse<&[u8], Vec<HttpHeader> >,
        do_parse!(
            result: many_till!(map!(separated_pair!(
                map_res!(ws!(take_until!(":")), str::from_utf8),
                tag_fast!(": "),
                map_res!(take_until!("\r"), str::from_utf8)), HttpHeader::from_tuple),
                tag_fast!("\r\n\r\n")) >>
            (result.0)
        )
    );
}

#[derive(Debug, Eq, PartialEq)]
/// A HTTP response representation
pub struct HttpResponse {
    /// The HTTP version
    pub version: HttpVersion,

    /// The HTTP response status code
    pub code: u16,

    /// The reason behind the status code
    pub reason: String,

    /// Available HTTP headers
    pub headers: Vec<HttpHeader>,
}

impl HttpResponse {
    named!(parse<&[u8], Layer>,
        ws!(do_parse!(
            // HTTP response parsing
            tag_fast!("HTTP/") >>
            version: call!(HttpVersion::parse) >>
            code: map_res!(map_res!(take_until!(" "), str::from_utf8), FromStr::from_str) >>
            reason: map_res!(take_until!("\r"), str::from_utf8) >>
            headers: call!(HttpHeader::parse) >>

            (Layer::Http(HttpPacket::Response(HttpResponse {
                version: version,
                code: code,
                reason: reason.to_owned(),
                headers: headers,
            })))
        ))
    );
}
