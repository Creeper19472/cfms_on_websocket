# QUIC/WebTransport Support

## Overview

The CFMS server now supports WebSockets over QUIC (WebTransport) as an alternative transport protocol to traditional WebSockets over TCP. QUIC provides several advantages:

- **Better performance**: Reduced connection setup time and improved throughput
- **Improved packet loss handling**: Better recovery from packet loss compared to TCP
- **Multiplexing**: Multiple streams without head-of-line blocking
- **Built-in encryption**: TLS 1.3 is built into the QUIC protocol

## Configuration

To enable QUIC/WebTransport support, modify your `config.toml`:

```toml
[server]
name = "CFMS WebSocket Server"
host = "localhost"
port = 5104
use_quic = true           # Enable QUIC transport
quic_port = 5104          # Port for QUIC (can be same as WebSocket port)
ssl_keyfile = "./content/ssl/key.pem"
ssl_certfile = "./content/ssl/cert.pem"
```

### Configuration Options

- `use_quic` (boolean, default: `false`): Enable QUIC/WebTransport transport instead of traditional WebSockets
- `quic_port` (integer): Port number for QUIC connections (defaults to same as `port` if not specified)

## How It Works

When QUIC mode is enabled:

1. The server creates a UDP socket (QUIC runs over UDP)
2. Incoming QUIC connections are handled using the `aioquic` library
3. WebTransport streams are wrapped to provide a WebSocket-like interface
4. All existing connection handlers work transparently with QUIC

The implementation uses a synchronous approach with threading to maintain compatibility with the existing synchronous WebSocket-based architecture.

## Transport Modes

### WebSocket Mode (Default)

```toml
use_quic = false
```

- Uses traditional WebSockets over TCP/TLS
- Compatible with all standard WebSocket clients
- Well-established and widely supported

### QUIC Mode

```toml
use_quic = true
```

- Uses WebTransport over QUIC
- Requires QUIC-capable clients
- Better performance in high-latency or packet-loss scenarios

## Client Requirements

### For WebSocket Mode
Any standard WebSocket client library that supports WSS (WebSocket Secure)

### For QUIC Mode
Clients need WebTransport support:
- Modern browsers with WebTransport API
- Custom clients using QUIC libraries like `aioquic`

## Implementation Details

The QUIC implementation consists of:

1. **QuicWebSocketAdapter**: Wraps QUIC streams to provide a WebSocket-like interface
   - Implements `recv()` and `send()` methods compatible with WebSocket connections
   - Handles data buffering and synchronization

2. **SyncQuicConnection**: Manages a single QUIC connection
   - Handles H3 and WebTransport protocol events
   - Routes data to appropriate stream handlers

3. **SyncQuicServer**: Main QUIC server
   - Listens for UDP datagrams
   - Manages multiple QUIC connections
   - Integrates with existing connection handler

## Performance Considerations

- QUIC performs best in networks with packet loss (>1%)
- Initial connection setup is faster than TCP+TLS
- Better multiplexing than HTTP/2 over TCP
- May have higher CPU usage than TCP due to user-space implementation

## Troubleshooting

### Server won't start with QUIC enabled

Check:
1. UDP port is available (not blocked by firewall)
2. SSL certificates are valid
3. `aioquic` library is installed

### Clients can't connect

Verify:
1. Client supports WebTransport
2. Firewall allows UDP traffic on the configured port
3. SSL certificate is trusted by the client

## Switching Between Modes

You can switch between WebSocket and QUIC modes by changing the `use_quic` setting in `config.toml`. The server needs to be restarted for the change to take effect.

Both modes use the same:
- Authentication system
- API endpoints
- Data formats
- Connection handlers

This ensures seamless operation regardless of the transport protocol used.
