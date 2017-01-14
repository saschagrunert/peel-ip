extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

#[test]
fn parse_http_request_success_get() {
    let mut parser = HttpParser;
    println!("{}", parser);
    let parsing_result =
        parser.parse(b"GET /some/path/ HTTP/1.0\r\nHost: myhost.com\r\nUser-agent: Myagent/0.1\r\n\r\nTest data",
                   None,
                   None)
            .unwrap()
            .1;
    let res = parsing_result.downcast_ref();
    assert_eq!(res,
               Some(&HttpPacket::Request(HttpRequest {
                   request_method: HttpRequestMethod::Get,
                   path: "/some/path/".to_owned(),
                   version: HttpVersion {
                       major: 1,
                       minor: 0,
                   },
                   headers: vec![HttpHeader {
                                     key: "Host".to_owned(),
                                     value: "myhost.com".to_owned(),
                                 },
                                 HttpHeader {
                                     key: "User-agent".to_owned(),
                                     value: "Myagent/0.1".to_owned(),
                                 }],
               })));
}

#[test]
fn parse_http_request_success_post() {
    let mut parser = HttpParser;
    let parsing_result = parser.parse(b"POST / HTTP/1.1\r\nHost: abc.com\r\n\r\n", None, None)
        .unwrap()
        .1;
    let res = parsing_result.downcast_ref();
    assert_eq!(res,
               Some(&HttpPacket::Request(HttpRequest {
                   request_method: HttpRequestMethod::Post,
                   path: "/".to_owned(),
                   version: HttpVersion {
                       major: 1,
                       minor: 1,
                   },
                   headers: vec![HttpHeader {
                                     key: "Host".to_owned(),
                                     value: "abc.com".to_owned(),
                                 }],
               })));
}

#[test]
fn parse_http_request_success_methods() {
    let mut parser = HttpParser;
    let header = " / HTTP/1.1\r\nHost: abc.com\r\n\r\n";
    let methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"];

    for method in &methods {
        let mut input = Vec::from(*method);
        input.extend_from_slice(header.as_bytes());
        parser.parse(&input, None, None).unwrap();
    }
}

#[test]
fn parse_http_request_failure_wrong_method() {
    let mut parser = HttpParser;
    assert!(parser.parse(b"GET", None, None).to_full_result().is_err());

    let input = b"GOT ";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_request_failure_wrong_path() {
    let mut parser = HttpParser;
    let input = b"GET HTTP/1.1";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_request_failure_wrong_version() {
    let mut parser = HttpParser;
    let input = b"GET / HTTP/1.k";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_request_failure_too_small() {
    let mut parser = HttpParser;
    let input = b"GET / HTTP/1.";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_response_success_moved() {
    let mut parser = HttpParser;
    let parsing_result = parser.parse(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://facebook.com\r\n\r\n",
               None,
               None)
        .unwrap()
        .1;
    let res = parsing_result.downcast_ref();
    assert_eq!(res,
               Some(&HttpPacket::Response(HttpResponse {
                   version: HttpVersion {
                       major: 1,
                       minor: 1,
                   },
                   code: 301,
                   reason: "Moved Permanently".to_owned(),
                   headers: vec![HttpHeader {
                                     key: "Location".to_owned(),
                                     value: "https://facebook.com".to_owned(),
                                 }],
               })));
}

#[test]
fn parse_http_response_success_ok() {
    let mut parser = HttpParser;
    let parsing_result = parser.parse(b"HTTP/1.0 200 OK\r\nHost: abc.com\r\n\r\n", None, None)
        .unwrap()
        .1;
    let res = parsing_result.downcast_ref();
    assert_eq!(res,
               Some(&HttpPacket::Response(HttpResponse {
                   version: HttpVersion {
                       major: 1,
                       minor: 0,
                   },
                   code: 200,
                   reason: "OK".to_owned(),
                   headers: vec![HttpHeader {
                                     key: "Host".to_owned(),
                                     value: "abc.com".to_owned(),
                                 }],
               })));
}

#[test]
fn parse_http_response_failure_wrong_protocol() {
    let mut parser = HttpParser;
    let input = b"HTTk/1.1";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_response_failure_too_small() {
    let mut parser = HttpParser;
    let input = b"HTTP/1.1";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}

#[test]
fn parse_http_response_failure_wrong_status_code() {
    let mut parser = HttpParser;
    let input = b"HTTP/1.1 20A OK\r\n";
    assert!(parser.parse(input, None, None).to_full_result().is_err());
}
