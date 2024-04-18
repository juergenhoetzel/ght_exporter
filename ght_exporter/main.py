import argparse
import logging
import sys

import gi
from prometheus_client import Gauge, start_http_server

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # type: ignore

log = logging.getLogger(__name__)

GOVEE_UUID = "0000ec88-0000-1000-8000-00805f9b34fb"


class GoveeTempExporter:
    temperature: Gauge
    humidity: Gauge
    battery: Gauge
    _dbus_connection: Gio.DBusConnection

    def _get_adapterpaths(self) -> list[str]:
        mgr_proxy = Gio.DBusProxy.new_sync(
            self._dbus_connection,
            Gio.DBusProxyFlags.NONE,
            None,
            "org.bluez",
            "/",
            "org.freedesktop.DBus.ObjectManager",
        )
        mngd_objs = mgr_proxy.GetManagedObjects()  # type: ignore
        return [obj_path for obj_path, obj_data in mngd_objs.items() if obj_data.get("org.bluez.Adapter1", {}).get("Powered")]

    def __init__(self):
        "Govee temperature prometheus exporter"

        self.temperature = Gauge("govee_temperature_degree", "Temperature in ℃", ["alias", "name", "address"])
        self.humidity = Gauge("govee_humidity_percent", "Humidity in percent", ["alias", "name", "address"])
        self.battery = Gauge("govee_battery_percent", "Battery in percent", ["alias", "name", "address"])
        self.rssi = Gauge("govee_rssi_dbm", "Received Signal Strength Indication (dBm)", ["alias", "name", "address"])
        self._dbus_connection = Gio.bus_get_sync(Gio.BusType.SYSTEM)

    def signal_callback(
        self,
        conn: Gio.DBusConnection,
        sender_name: str,
        object_path: str,
        interface_name: str,
        signal_name: str,
        parameters_variant: GLib.Variant,
    ):
        parameters = parameters_variant.unpack()

        if len(parameters) < 2 or not isinstance(parameters[1], dict):
            return

        bz_data = parameters[1].get("org.bluez.Device1", {})
        if (data := bz_data.get("ManufacturerData", {}).get(1)) and len(data) >= 6:
            log.debug(f"ManufacturerData: {data}")
            alias = bz_data.get("Alias")
            name = bz_data.get("Name")
            rssi = bz_data.get("RSSI")
            address = bz_data.get("Address")
            # temp, humi = decode_temp_humid(data[2:5])
            n = int.from_bytes(data[2:5], "big", signed=True)
            temp = n // 1000 / 10
            hum = n % 1000 / 10
            batt = int(data[5] & 0x7F)
            err = bool(data[5] & 0x80)
            if not err:
                log.info(f"{alias}: Temperature: {temp}℃ , Humidity: {hum}%, Battery: {batt}%")
                self.temperature.labels(alias=alias, name=name, address=address).set(temp)
                self.humidity.labels(alias=alias, name=name, address=address).set(hum)
                self.battery.labels(alias=alias, name=name, address=address).set(batt)
                self.rssi.labels(alias=alias, name=name, address=address).set(rssi)

    def bluez_appeared(self, conn: Gio.DBusConnection, name: str, _):
        log.debug("'org.bluez' is available")
        if not (adapter_paths := self._get_adapterpaths()):
            log.critical("No bluetooth adapter available")
            return
        log.debug(f"Using first bluetooth adapter {adapter_paths[0]}")  # Fixme: Option, when multiple adapters?
        adapter_proxy: Gio.DBusProxy = Gio.DBusProxy.new_sync(self._dbus_connection, Gio.DBusProxyFlags.NONE, None, "org.bluez", adapter_paths[0], "org.bluez.Adapter1")

        logging.debug(f"Starting discovery on {adapter_paths[0]}")
        adapter_proxy.SetDiscoveryFilter("(a{sv})", {"UUIDs": GLib.Variant("as", [GOVEE_UUID])})  # type: ignore
        adapter_proxy.StartDiscovery()  # type: ignore
        conn.signal_subscribe(name, None, None, None, None, Gio.DBusSignalFlags.NONE, self.signal_callback)

    def start(self):
        watcher_id = Gio.bus_watch_name_on_connection(self._dbus_connection, "org.bluez", Gio.BusNameWatcherFlags.NONE, self.bluez_appeared, None)


def main():
    parser = argparse.ArgumentParser(prog="govee_temp_exporter", description="Govee Bluetooth Low Energy Temperature and Humidity exporter")
    loglevels = {
        "DEBUG": logging.debug,
        "INFO": logging.info,
        "WARNING": logging.warning,
        "ERROR": logging.error,
        "CRITICAL": logging.critical,
    }
    parser.add_argument(
        "-l",
        "--loglevel",
        choices=loglevels.keys(),
        help="log level; one of: CRITICAL, ERROR, WARNING, INFO, DEBUG",
        default="WARNING",
    )
    parser.add_argument("-p", "--port", help="Port on which to expose metrics", type=int, default="8080")
    args = parser.parse_args(sys.argv[1:])

    logging.basicConfig(
        level=args.loglevel,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    # Start up the server to expose the metrics.
    start_http_server(args.port)
    ge = GoveeTempExporter()
    ge.start()
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
