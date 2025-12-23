# CFMS On Websocket

CFMS (Confidential File Management System), is a complete solution for 
managing confidential documents. This is the repository used to 
implement server functionality.

The Project is still in the early stages of development and cannot 
guarantee the security and stability of running the Service. 

Welcome to Github Issues for improvements and bug reports.

You can access the Chinese Simplified version of the development 
documentation here: [CFMS Server Documentation][doc-url] 
However, Since this document was written specifically for the previous 
version of CFMS, much of it may be outdated. If possible, use code 
comments as the primary reference.

[doc-url]: https://cfms-server-doc.readthedocs.io/zh_CN/latest

## Features

- **Multiple Transport Protocols**: Support for both traditional WebSockets and WebSockets over QUIC (WebTransport)
- **QUIC/WebTransport Support**: Improved performance with QUIC protocol for better handling of packet loss and reduced latency
- Comprehensive document management system
- User and group permission management
- SSL/TLS encryption support

For more information about QUIC/WebTransport support, see [QUIC_SUPPORT.md](QUIC_SUPPORT.md).

## Testing

This repository includes an automated test suite built with pytest. To run the tests:

```bash
# Install dependencies
uv sync --dev

# Run all tests
uv run pytest

# Run specific test files
uv run pytest tests/test_basic.py
```

For more information about the test suite, see [tests/README.md](tests/README.md).

## Alpha Test

This is a project that is under active development and we are looking 
for people interested in the project to participate in testing. We are 
well aware that the system still has huge shortcomings as a functional 
solution – and we want as many people as possible to join in improving 
them.