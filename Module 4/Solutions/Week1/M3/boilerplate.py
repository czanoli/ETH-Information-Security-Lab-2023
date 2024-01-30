""" Command server boilerplate for the Applied Cryptography labs

This module provides:
    1. A class `CommandServer` that can be subclassed and that provides utility functions
       for communicating using JSON payloads
    2. A decorator `on_command` that registers a function as the handler when receiving
       messages from the client with a specific command
    3. A decorator `on_startup` that registers a function as the method to run as soon as
       a client connects
"""

import socket
import socketserver
import json
from typing import Optional, Callable, Dict, Any, TypeVar

# A type variable for any instance of a class that inherits from CommandServer
CommandServerChild = TypeVar("CommandServerChild", bound="CommandServer")

# A init handler takes self, and returns nothing
InitHandler = Callable[[CommandServerChild], None]

# A command handler takes self, an unmarshalled JSON, and returns nothing
Handler = Callable[[CommandServerChild, dict[str, Any]], None]

# A message is a dict that can be converted to JSON
# Note that JSON specifies that keys *must* be strings and will force
# them to be string if necessary.
Message = dict[str, Any]


class CommandServer(socketserver.StreamRequestHandler):
    """Command Handler base class

    This class should be extended to include command handlers
    """

    def __new__(cls, *args, **kwargs):
        # pylint: disable=unused-argument

        if cls is CommandServer:
            raise TypeError("Cannot instantiate CommandServer directly")
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        self.running = True
        super().__init__(*args, **kwargs)

    def send_message(self, obj: Message):
        """Send a JSON-formatted response to the client.

        Args:
            obj (dict): the response object
        """
        res = json.dumps(obj) + "\n"

        try:
            self.wfile.write(res.encode())
            self.wfile.flush()
        except BrokenPipeError:
            # Client has disconnected, close connection silently
            self.close_connection()

    def read_message(self) -> Message:
        """Parse a JSON-formatted message from the client.

        Returns:
            dict: a dictionary representing the input JSON message.
        """
        msg = self.rfile.readline()
        return json.loads(msg)

    def close_connection(self) -> None:
        """Close the connection by exiting the `handle` method"""

        self.running = False

    def handle(self) -> None:
        """Handle messages from the client"""

        # Run setup function
        on_startup.run_startup_handler(self)

        while self.running:
            # Try to parse the message
            try:
                msg = self.read_message()
            except json.decoder.JSONDecodeError:
                self.send_message({"res": "Failed to execute command: malformed JSON"})
                continue

            # Ensure that the `command` field exists
            if "command" not in msg:
                self.send_message(
                    {"res": "Failed to execute command: `command` field missing"}
                )
                continue

            # Fetch handler for the requested `command`
            try:
                handler = on_command.get_command_handler(msg["command"])
            except KeyError:
                self.send_message(
                    {
                        "res": "Failed to execute command: `command` name not valid."
                        + f" Valid commands are: {on_command.list_commands()}"
                    }
                )
                continue

            # Call the handler
            # All errors thrown in the handler should be managed by the handler itself
            # Otherwise, the connection will close itself without sending any info back
            handler(self, msg)

    def finish(self) -> None:
        """Clean up after the client disconnects. Automatically called by TCPServer"""
        self.wfile.close()

    @classmethod
    def start_server(cls, host: str, port: int, ipv6: bool = False, **kwargs) -> None:
        """Start the TCP server on the given port

        Args:
            host (str): the host on which to listen
            port (int): the TCP port on which to listen
            kwargs: all the additional parameters that will be injected
                    into the request handler
        """

        # Inject our values by partial application to the class
        cls_injected = lambda request, client_address, server: cls(**kwargs, request=request, client_address=client_address, server=server)

        class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            """A TCP Server that allows for multiple simultaneous connections and port reuse"""

            address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
            allow_reuse_address = True


        with TCPServer((host, port), cls_injected) as server:
            server.serve_forever()


# Forgive me for breaking PEP8 but I like decorators to be camel case :)


# pylint: disable=invalid-name
class on_command:
    """A decorator class used to register a handler to be called on a specified command"""

    _handlers: Dict[str, Handler] = {}

    def __init__(self, command: str):
        self.command = command

    def __call__(self, handler: Handler) -> Handler:
        self._handlers[self.command] = handler
        return handler

    @classmethod
    def get_command_handler(cls, command: str) -> Handler:
        """Returns the handler for the specified command

        Raises KeyError if the command has no registered handler
        """

        return cls._handlers[command]

    @classmethod
    def list_commands(cls) -> list[str]:
        """Returns the list of all registered commands"""

        return list(cls._handlers.keys())


class on_startup:
    """A decorator class used to register a handler to be called at startup"""

    _handler: Optional[InitHandler] = None

    def __call__(self, handler: InitHandler) -> InitHandler:
        self.__class__._handler = handler
        return handler

    @classmethod
    def run_startup_handler(cls, obj: CommandServer):
        """Executes the handler registered for startup, if present"""

        if cls._handler is not None:
            cls._handler(obj)
