"""
QUIC/WebTransport server implementation for CFMS using synchronous interface.

This module provides a WebSocket-like interface over QUIC using aioquic's
core QUIC implementation wrapped with synchronous threading patterns.
"""

import socket
import ssl
import threading
import time
from typing import Optional, Callable, Dict
import struct

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    QuicEvent,
    StreamDataReceived,
    ConnectionTerminated,
    StreamReset,
)
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import (
    H3Event,
    DataReceived,
    HeadersReceived,
    WebTransportStreamDataReceived,
)

from include.util.log import getCustomLogger

logger = getCustomLogger("quic_server", filepath="./content/logs/quic_server.log")


class QuicWebSocketAdapter:
    """
    Adapter that makes a QUIC stream behave like a WebSocket connection.
    
    This class provides the same interface as websockets.sync.server.ServerConnection
    so it can be used with the existing connection handler.
    """
    
    def __init__(self, connection: 'SyncQuicConnection', stream_id: int, remote_address: tuple):
        self.connection = connection
        self.stream_id = stream_id
        self.remote_address = remote_address
        self._recv_queue: list = []
        self._recv_lock = threading.Lock()
        self._closed = False
        
    def recv(self) -> Optional[bytes]:
        """
        Receive data from the QUIC stream (blocking, synchronous interface).
        
        Returns:
            Received data as bytes, or None if connection is closed
        """
        while not self._closed:
            with self._recv_lock:
                if self._recv_queue:
                    return self._recv_queue.pop(0)
            
            # Wait a bit for data
            time.sleep(0.01)
            
            # Check if connection is closed
            if self._closed or self.connection.is_closing:
                return None
                
        return None
    
    def send(self, data: bytes) -> None:
        """
        Send data over the QUIC stream.
        
        Args:
            data: Data to send as bytes
        """
        if self._closed:
            raise ConnectionError("Connection is closed")
            
        try:
            self.connection.send_stream_data(self.stream_id, data)
        except Exception as e:
            logger.error(f"Error sending data: {e}", exc_info=True)
            self._closed = True
            raise
    
    def close(self) -> None:
        """Close the QUIC stream."""
        if not self._closed:
            self._closed = True
    
    def _enqueue_data(self, data: bytes) -> None:
        """Internal method to enqueue received data."""
        if not self._closed:
            with self._recv_lock:
                self._recv_queue.append(data)


class SyncQuicConnection:
    """
    Synchronous QUIC connection handler.
    """
    
    def __init__(self, quic: QuicConnection, sock: socket.socket, addr: tuple, handler: Callable):
        self.quic = quic
        self.socket = sock
        self.remote_addr = addr
        self.handler = handler
        self.h3 = H3Connection(quic)
        self.streams: Dict[int, QuicWebSocketAdapter] = {}
        self.is_closing = False
        self._lock = threading.Lock()
        
    def handle_events(self) -> None:
        """Process all pending QUIC events."""
        with self._lock:
            while True:
                event = self.quic.next_event()
                if event is None:
                    break
                    
                if isinstance(event, StreamDataReceived):
                    # Process H3 events
                    for h3_event in self.h3.handle_event(event):
                        self._handle_h3_event(h3_event)
                        
                elif isinstance(event, ConnectionTerminated):
                    logger.info(f"Connection terminated: {event}")
                    self.is_closing = True
                    for adapter in list(self.streams.values()):
                        adapter.close()
                    self.streams.clear()
                    
                elif isinstance(event, StreamReset):
                    stream_id = event.stream_id
                    if stream_id in self.streams:
                        self.streams[stream_id].close()
                        del self.streams[stream_id]
    
    def _handle_h3_event(self, event: H3Event) -> None:
        """Handle HTTP/3 events."""
        if isinstance(event, HeadersReceived):
            stream_id = event.stream_id
            headers = dict(event.headers)
            
            # Check if this is a WebTransport request
            if headers.get(b":protocol") == b"webtransport":
                # Create adapter for this stream
                adapter = QuicWebSocketAdapter(self, stream_id, self.remote_addr)
                self.streams[stream_id] = adapter
                
                # Send acceptance response
                self.h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":status", b"200"),
                        (b"sec-webtransport-http3-draft", b"draft02"),
                    ],
                )
                
                # Send datagrams
                datagrams = self.quic.datagrams_to_send(now=time.time())
                for datagram, addr in datagrams:
                    self.socket.sendto(datagram, addr)
                
                # Handle the connection in a separate thread
                threading.Thread(
                    target=self._handle_stream,
                    args=(adapter,),
                    daemon=True
                ).start()
                
        elif isinstance(event, DataReceived) or isinstance(event, WebTransportStreamDataReceived):
            stream_id = event.stream_id
            if stream_id in self.streams:
                self.streams[stream_id]._enqueue_data(event.data)
    
    def _handle_stream(self, adapter: QuicWebSocketAdapter) -> None:
        """Handle a stream using the connection handler."""
        try:
            self.handler(adapter)
        except Exception as e:
            logger.error(f"Error handling stream: {e}", exc_info=True)
        finally:
            adapter.close()
            if adapter.stream_id in self.streams:
                with self._lock:
                    del self.streams[adapter.stream_id]
    
    def send_stream_data(self, stream_id: int, data: bytes) -> None:
        """Send data on a stream."""
        with self._lock:
            self.h3.send_data(stream_id=stream_id, data=data, end_stream=False)
            
            # Send datagrams
            datagrams = self.quic.datagrams_to_send(now=time.time())
            for datagram, addr in datagrams:
                self.socket.sendto(datagram, addr)


class SyncQuicServer:
    """
    Synchronous QUIC server.
    """
    
    def __init__(
        self,
        handler: Callable,
        host: str,
        port: int,
        ssl_certfile: str,
        ssl_keyfile: str,
    ):
        self.handler = handler
        self.host = host
        self.port = port
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.connections: Dict[tuple, SyncQuicConnection] = {}
        self.running = False
        
        # Configure QUIC
        self.configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=False,
            max_datagram_frame_size=65536,
        )
        self.configuration.load_cert_chain(ssl_certfile, ssl_keyfile)
        
        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.settimeout(1.0)  # 1 second timeout for recv
        
        logger.info(f"QUIC server listening on {host}:{port}")
    
    def serve_forever(self) -> None:
        """Run the server loop."""
        self.running = True
        logger.info("QUIC server started")
        
        try:
            while self.running:
                try:
                    # Receive datagram
                    data, addr = self.socket.recvfrom(65536)
                    
                    # Get or create connection for this address
                    if addr not in self.connections:
                        # Create new QUIC connection
                        quic = QuicConnection(
                            configuration=self.configuration,
                            original_destination_connection_id=None,
                        )
                        self.connections[addr] = SyncQuicConnection(
                            quic, self.socket, addr, self.handler
                        )
                    
                    conn = self.connections[addr]
                    
                    # Feed data to QUIC connection
                    conn.quic.receive_datagram(data, addr, now=time.time())
                    
                    # Process events
                    conn.handle_events()
                    
                    # Send outgoing datagrams
                    datagrams = conn.quic.datagrams_to_send(now=time.time())
                    for datagram, dest_addr in datagrams:
                        self.socket.sendto(datagram, dest_addr)
                    
                    # Clean up closed connections
                    if conn.is_closing:
                        del self.connections[addr]
                        
                except socket.timeout:
                    # Timeout is normal, just continue
                    # Clean up any timed-out connections
                    now = time.time()
                    to_remove = []
                    for addr, conn in self.connections.items():
                        # Send keep-alive if needed
                        datagrams = conn.quic.datagrams_to_send(now=now)
                        for datagram, dest_addr in datagrams:
                            self.socket.sendto(datagram, dest_addr)
                        
                        if conn.is_closing:
                            to_remove.append(addr)
                    
                    for addr in to_remove:
                        del self.connections[addr]
                        
        except KeyboardInterrupt:
            logger.info("Server interrupted")
        finally:
            self.close()
    
    def close(self) -> None:
        """Close the server and all connections."""
        logger.info("Closing QUIC server")
        self.running = False
        
        # Close all connections
        for conn in list(self.connections.values()):
            conn.is_closing = True
            for adapter in list(conn.streams.values()):
                adapter.close()
        
        self.connections.clear()
        self.socket.close()


def create_quic_server(
    handler: Callable,
    host: str,
    port: int,
    ssl_certfile: str,
    ssl_keyfile: str,
) -> SyncQuicServer:
    """
    Create a synchronous QUIC server.
    
    Args:
        handler: Connection handler function
        host: Host to bind to
        port: Port to bind to
        ssl_certfile: Path to SSL certificate file
        ssl_keyfile: Path to SSL key file
        
    Returns:
        SyncQuicServer instance
    """
    return SyncQuicServer(handler, host, port, ssl_certfile, ssl_keyfile)
