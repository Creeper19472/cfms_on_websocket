"""
QUIC/WebTransport server implementation for CFMS.

This module provides a WebSocket-like interface over QUIC using aioquic.
It wraps QUIC connections to be compatible with the existing WebSocket-based
connection handler.
"""

import asyncio
import logging
import ssl
from typing import Optional, Callable
from collections.abc import Awaitable

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated
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
    
    def __init__(self, protocol: 'QuicServerProtocol', stream_id: int, remote_address: tuple):
        self.protocol = protocol
        self.stream_id = stream_id
        self.remote_address = remote_address
        self._recv_queue: asyncio.Queue = asyncio.Queue()
        self._closed = False
        
    def recv(self) -> Optional[bytes]:
        """
        Receive data from the QUIC stream (blocking, synchronous interface).
        
        Returns:
            Received data as bytes, or None if connection is closed
        """
        if self._closed:
            return None
            
        try:
            # Get the current event loop
            loop = asyncio.get_event_loop()
            # Wait for data with a timeout
            data = loop.run_until_complete(
                asyncio.wait_for(self._recv_queue.get(), timeout=0.1)
            )
            return data
        except asyncio.TimeoutError:
            # Check if connection is still alive
            if self._closed:
                return None
            # Return empty to continue polling
            return b""
        except Exception as e:
            logger.error(f"Error receiving data: {e}", exc_info=True)
            self._closed = True
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
            self.protocol.send_stream_data(self.stream_id, data)
        except Exception as e:
            logger.error(f"Error sending data: {e}", exc_info=True)
            self._closed = True
            raise
    
    def close(self) -> None:
        """Close the QUIC stream."""
        if not self._closed:
            self._closed = True
            try:
                self.protocol.close_stream(self.stream_id)
            except Exception as e:
                logger.debug(f"Error closing stream: {e}")
    
    def _enqueue_data(self, data: bytes) -> None:
        """Internal method to enqueue received data."""
        if not self._closed:
            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(self._recv_queue.put_nowait, data)
            except Exception as e:
                logger.error(f"Error enqueueing data: {e}", exc_info=True)


class QuicServerProtocol(QuicConnectionProtocol):
    """
    QUIC server protocol handler that processes WebTransport connections.
    """
    
    def __init__(self, *args, handler: Callable, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self._h3 = H3Connection(self._quic)
        self._streams: dict[int, QuicWebSocketAdapter] = {}
        
    def quic_event_received(self, event: QuicEvent) -> None:
        """
        Handle QUIC events.
        
        Args:
            event: The QUIC event to process
        """
        if isinstance(event, StreamDataReceived):
            # Process H3 events
            for h3_event in self._h3.handle_event(event):
                self._h3_event_received(h3_event)
        elif isinstance(event, ConnectionTerminated):
            # Clean up all streams
            for adapter in list(self._streams.values()):
                adapter.close()
            self._streams.clear()
    
    def _h3_event_received(self, event: H3Event) -> None:
        """
        Handle HTTP/3 events.
        
        Args:
            event: The H3 event to process
        """
        if isinstance(event, HeadersReceived):
            # New stream/connection
            stream_id = event.stream_id
            headers = dict(event.headers)
            
            # Check if this is a WebTransport request
            if headers.get(b":protocol") == b"webtransport":
                # Create adapter for this stream
                remote_address = self._quic._network_paths[0].addr
                adapter = QuicWebSocketAdapter(self, stream_id, remote_address)
                self._streams[stream_id] = adapter
                
                # Send acceptance response
                self._h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":status", b"200"),
                        (b"sec-webtransport-http3-draft", b"draft02"),
                    ],
                )
                self.transmit()
                
                # Handle the connection in a separate task
                asyncio.create_task(self._handle_connection(adapter))
                
        elif isinstance(event, DataReceived) or isinstance(event, WebTransportStreamDataReceived):
            # Data received on existing stream
            stream_id = event.stream_id
            if stream_id in self._streams:
                self._streams[stream_id]._enqueue_data(event.data)
    
    async def _handle_connection(self, adapter: QuicWebSocketAdapter) -> None:
        """
        Handle a WebTransport connection using the existing handler.
        
        Args:
            adapter: The QuicWebSocketAdapter wrapping the connection
        """
        try:
            # Run the handler in an executor to support the sync interface
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.handler, adapter)
        except Exception as e:
            logger.error(f"Error handling connection: {e}", exc_info=True)
        finally:
            adapter.close()
            if adapter.stream_id in self._streams:
                del self._streams[adapter.stream_id]
    
    def send_stream_data(self, stream_id: int, data: bytes) -> None:
        """
        Send data on a stream.
        
        Args:
            stream_id: The stream ID
            data: Data to send
        """
        self._h3.send_data(stream_id=stream_id, data=data, end_stream=False)
        self.transmit()
    
    def close_stream(self, stream_id: int) -> None:
        """
        Close a stream.
        
        Args:
            stream_id: The stream ID to close
        """
        try:
            self._h3.send_data(stream_id=stream_id, data=b"", end_stream=True)
            self.transmit()
        except Exception as e:
            logger.debug(f"Error closing stream {stream_id}: {e}")


def create_quic_server(
    handler: Callable,
    host: str,
    port: int,
    ssl_certfile: str,
    ssl_keyfile: str,
) -> Awaitable:
    """
    Create and start a QUIC server.
    
    Args:
        handler: Connection handler function
        host: Host to bind to
        port: Port to bind to
        ssl_certfile: Path to SSL certificate file
        ssl_keyfile: Path to SSL key file
        
    Returns:
        Awaitable server task
    """
    # Configure QUIC
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
    )
    
    # Load SSL certificate and key
    configuration.load_cert_chain(ssl_certfile, ssl_keyfile)
    
    logger.info(f"Starting QUIC server on {host}:{port}")
    
    # Create protocol factory
    def create_protocol(*args, **kwargs):
        return QuicServerProtocol(*args, handler=handler, **kwargs)
    
    # Start server
    return serve(
        host=host,
        port=port,
        configuration=configuration,
        create_protocol=create_protocol,
    )
