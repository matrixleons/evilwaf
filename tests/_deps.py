import sys
import types


def install_dependency_stubs():
    if "tls_client" not in sys.modules:
        tls_client = types.ModuleType("tls_client")

        class DummySession:
            def __init__(self, *args, **kwargs):
                pass

        tls_client.Session = DummySession
        sys.modules["tls_client"] = tls_client

    if "scapy" not in sys.modules:
        scapy = types.ModuleType("scapy")
        scapy_all = types.ModuleType("scapy.all")

        class DummyPacket:
            def __truediv__(self, other):
                return self

            def haslayer(self, layer):
                return False

        def ip(*args, **kwargs):
            return DummyPacket()

        def tcp(*args, **kwargs):
            return DummyPacket()

        def sr1(*args, **kwargs):
            return None

        scapy_all.IP = ip
        scapy_all.TCP = tcp
        scapy_all.sr1 = sr1
        sys.modules["scapy"] = scapy
        sys.modules["scapy.all"] = scapy_all

    if "stem" not in sys.modules:
        stem = types.ModuleType("stem")
        stem.Signal = types.SimpleNamespace(NEWNYM="NEWNYM")
        stem_control = types.ModuleType("stem.control")

        class DummyController:
            @classmethod
            def from_port(cls, port=None):
                return cls()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def authenticate(self, password=None):
                return None

            def signal(self, sig):
                return None

        stem_control.Controller = DummyController
        sys.modules["stem"] = stem
        sys.modules["stem.control"] = stem_control

    if "socks" not in sys.modules:
        socks = types.ModuleType("socks")
        socks.SOCKS5 = 1
        socks.SOCKS4 = 2
        socks.HTTP = 3

        class DummySock:
            def close(self):
                return None

        def create_connection(*args, **kwargs):
            return DummySock()

        socks.create_connection = create_connection
        sys.modules["socks"] = socks
