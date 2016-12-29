# peel-ip
[![Build Status](https://travis-ci.org/saschagrunert/peel-ip.svg)](https://travis-ci.org/saschagrunert/peel-ip) [![Build status](https://ci.appveyor.com/api/projects/status/1c6d93otbd8dgswc?svg=true)](https://ci.appveyor.com/project/saschagrunert/peel-ip) [![Coverage Status](https://coveralls.io/repos/github/saschagrunert/peel-ip/badge.svg?branch=master)](https://coveralls.io/github/saschagrunert/peel-ip?branch=master) [![master doc peel-ip](https://img.shields.io/badge/master_doc-peel_ip-blue.svg)](https://saschagrunert.github.io/peel-ip) [![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/saschagrunert/peel-ip/blob/master/LICENSE) [![Crates.io](https://img.shields.io/crates/v/peel-ip.svg)](https://crates.io/crates/peel-ip) [![doc.rs](https://docs.rs/peel-ip/badge.svg)](https://docs.rs/peel-ip)
## Packet parsing for the Internet Protocol Suite
The base for this crate is [Peel](https://github.com/saschagrunert/peel), a dynamic parsing tree using arena based
memory management. The current structure of the parsing tree look like this:

![Parser diagram](.github/structure.png)

This means in detail, that beside the usual protocol stack (like: `[Ethernet, IPv4, TCP, HTTP]`) IP in IP combinations
are supported as well (like `[Ethernet, IPv4, IPv6, TCP, HTTP]`).

## Planned features:
- Use the [Path](https://github.com/saschagrunert/path) crate to provide connection identification
- Add support packet reassembly
- Add more protocols of the TCP/IP suite

## Contributing
You want to contribute to this project? Wow, thanks! So please just fork it and send me a pull request.
