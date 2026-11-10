"""
Meshtastic MQTT Protobuf to JSON Converter

Subscribes to Protobuf MQTT topics, converts packets to JSON, and republishes them.
Supports multi-level region topics (e.g. US/AZ/Tucson or US/AZ/+), multiple channel PSKs,
and Home Assistant Add-on configuration (/data/options.json).
"""

import argparse
import base64
import json
import logging
import os
import struct
import paho.mqtt.client as mqtt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from meshtastic import mesh_pb2, mqtt_pb2, telemetry_pb2, portnums_pb2
except ImportError:
    print("Error: Install dependencies with: pip install -r requirements.txt")
    exit(1)

# Optional payload types (absent in older meshtastic builds).
try:
    from meshtastic import remote_hardware_pb2
except ImportError:
    remote_hardware_pb2 = None
try:
    from meshtastic import paxcount_pb2
except ImportError:
    paxcount_pb2 = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_MESHTASTIC_KEY = bytearray([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
])
VALID_PORTNUMS = set(portnums_pb2.PortNum.values()) - {portnums_pb2.PortNum.UNKNOWN_APP}


def has_no_unknown_fields(msg):
    try:
        return len(msg.UnknownFields()) == 0
    except Exception:
        return True


class MeshtasticConverter:
    def __init__(self, broker, port, username, password, region, root_topic, psk=None, channels=None):
        self.broker = broker
        self.port = port
        self.region = (region or "").strip("/")
        self.root_topic = (root_topic or "msh").strip("/")
        self.channel_psks = {}
        self.fallback_psks = []

        # Parse per-channel PSKs
        if channels:
            for item in channels:
                if isinstance(item, dict):
                    ch_name = (item.get("name") or item.get("channel") or "").strip()
                    ch_psk = item.get("psk") if item.get("psk") is not None else item.get("key")
                    if ch_name and ch_psk is not None:
                        decoded = self.decode_psk(str(ch_psk))
                        if decoded:
                            self.channel_psks.setdefault(ch_name.lower(), []).append(decoded)
                elif isinstance(item, str) and ":" in item:
                    ch_name, ch_psk = item.split(":", 1)
                    decoded = self.decode_psk(ch_psk.strip())
                    if ch_name.strip() and decoded:
                        self.channel_psks.setdefault(ch_name.strip().lower(), []).append(decoded)

        # Parse fallback PSK(s) (supports comma-separated list)
        if psk:
            for part in str(psk).split(","):
                part = part.strip()
                if part:
                    decoded = self.decode_psk(part)
                    if decoded and decoded not in self.fallback_psks:
                        self.fallback_psks.append(decoded)

        self.psk = self.fallback_psks[0] if self.fallback_psks else None

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        if username:
            self.client.username_pw_set(username, password)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    @staticmethod
    def expand_key(raw_psk):
        if not raw_psk:
            return None
        if len(raw_psk) == 1:
            if raw_psk[0] == 0:
                return None
            key = bytearray(DEFAULT_MESHTASTIC_KEY)
            if raw_psk[0] > 1:
                key[-1] = (key[-1] + (raw_psk[0] - 1)) & 0xFF
            return bytes(key)
        return bytes(raw_psk)

    def decode_psk(self, psk_str):
        if psk_str is None:
            return None
        psk_str = str(psk_str).strip()
        if not psk_str or psk_str.lower() in ('none', 'null', ''):
            return None

        if psk_str.lower() in ('default', '1', 'aq=='):
            return self.expand_key(bytes([1]))

        if psk_str.startswith('base64:'):
            try:
                return self.expand_key(base64.b64decode(psk_str[7:].strip()))
            except Exception as e:
                logger.error(f"Could not decode base64 PSK '{psk_str}': {e}")
                return None

        if psk_str.startswith('0x') or psk_str.startswith('0X'):
            try:
                return self.expand_key(bytes.fromhex(psk_str[2:].strip()))
            except ValueError as e:
                logger.error(f"Could not decode hex PSK '{psk_str}': {e}")
                return None

        # Prefer hex only when length matches 1, 16, or 32 byte hex representations (2, 32, or 64 hex chars)
        if len(psk_str) in (2, 32, 64):
            try:
                raw = bytes.fromhex(psk_str)
                if len(raw) in (1, 16, 32):
                    return self.expand_key(raw)
            except ValueError:
                pass

        try:
            raw = base64.b64decode(psk_str)
            if len(raw) in (1, 16, 32):
                return self.expand_key(raw)
        except Exception:
            pass

        try:
            return self.expand_key(bytes.fromhex(psk_str))
        except ValueError:
            pass

        try:
            return self.expand_key(base64.b64decode(psk_str))
        except Exception:
            pass

        logger.error(f"Could not decode PSK: {psk_str}")
        return None

    def get_candidate_keys(self, channel_name=None):
        candidates = []
        if channel_name:
            for k in self.channel_psks.get(channel_name.lower(), []):
                if k not in candidates:
                    candidates.append(k)
        for k in self.fallback_psks:
            if k not in candidates:
                candidates.append(k)
        for ch_keys in self.channel_psks.values():
            for k in ch_keys:
                if k not in candidates:
                    candidates.append(k)
        return candidates

    def decrypt_packet(self, packet, channel_name=None, key_override=None):
        if not packet.HasField('encrypted') or len(packet.encrypted) == 0:
            return False

        candidates = [key_override] if key_override else self.get_candidate_keys(channel_name)
        if not candidates:
            return False

        packet_id = packet.id
        from_node = getattr(packet, 'from')
        nonce = struct.pack('<I', packet_id) + bytes(4) + struct.pack('<I', from_node) + bytes(4)

        for key in candidates:
            try:
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(packet.encrypted) + decryptor.finalize()

                candidate_data = mesh_pb2.Data()
                candidate_data.ParseFromString(decrypted)
                if (
                    candidate_data.portnum in VALID_PORTNUMS
                    and len(candidate_data.payload) > 0
                    and has_no_unknown_fields(candidate_data)
                ):
                    packet.decoded.CopyFrom(candidate_data)
                    return True
            except Exception as e:
                logger.debug(f"Decryption attempt failed for channel {channel_name}: {e}")
                continue

        return False

    def encrypt_packet(self, packet, channel_name=None):
        candidates = self.get_candidate_keys(channel_name)
        if not candidates:
            return

        if not packet.HasField('decoded'):
            return

        try:
            key = candidates[0]
            plaintext = packet.decoded.SerializeToString()

            packet_id = packet.id if packet.id else 0
            from_node = getattr(packet, 'from')
            nonce = struct.pack('<I', packet_id) + bytes(4) + struct.pack('<I', from_node) + bytes(4)

            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(plaintext) + encryptor.finalize()

            packet.encrypted = encrypted
            packet.ClearField('decoded')

        except Exception as e:
            logger.error(f"Encryption failed: {e}")

    def _build_topic_prefix(self):
        if self.region:
            return f"{self.root_topic}/{self.region}"
        return self.root_topic

    def on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            prefix = self._build_topic_prefix()
            protobuf_topic = f"{prefix}/2/e/#"
            json_topic = f"{prefix}/2/json/#"

            logger.info(f"Connected to {self.broker}:{self.port}")
            logger.info(f"Subscribing to protobuf: {protobuf_topic}")
            logger.info(f"Subscribing to JSON downlink: {json_topic}")
            if self.channel_psks:
                logger.info(f"Configured channel keys for: {', '.join(self.channel_psks.keys())}")

            client.subscribe(protobuf_topic)
            client.subscribe(json_topic)
        else:
            logger.error(f"Connection failed with code {rc}")

    def on_message(self, client, userdata, msg):
        try:
            if '/2/json/' in msg.topic:
                try:
                    json_data = json.loads(msg.payload.decode('utf-8'))
                    if isinstance(json_data, dict) and 'type' in json_data and str(json_data['type']).startswith('send'):
                        self.handle_json_to_protobuf(client, msg, json_data)
                    return
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.debug(f"Could not parse JSON on topic: {msg.topic}")
                    return

            if '/2/e/' in msg.topic:
                self.handle_protobuf_to_json(client, msg)
        except Exception as e:
            logger.error(f"Error processing message on {msg.topic}: {e}")

    def handle_json_to_protobuf(self, client, msg, json_data):
        try:
            logger.debug(f"Received JSON downlink: {json_data}")

            if '/2/json/' in msg.topic:
                prefix, suffix = msg.topic.split('/2/json/', 1)
                suffix_parts = [p for p in suffix.split('/') if p]
                channel_name = suffix_parts[0] if suffix_parts else "LongFast"
            else:
                prefix = self._build_topic_prefix()
                channel_name = "LongFast"

            packet = mesh_pb2.MeshPacket()
            setattr(packet, 'from', json_data.get('from', 0))
            packet.to = json_data.get('to', 0xFFFFFFFF)
            packet.id = json_data.get('id', 0)

            if 'channel' in json_data:
                packet.channel = json_data['channel']

            # Firmware used camelCase "hopLimit"; accept both spellings.
            if 'hopLimit' in json_data:
                packet.hop_limit = json_data['hopLimit']
            elif 'hop_limit' in json_data:
                packet.hop_limit = json_data['hop_limit']

            msg_type = json_data.get('type', '')
            payload_data = json_data.get('payload', {})

            if msg_type == 'sendtext':
                packet.decoded.portnum = portnums_pb2.PortNum.TEXT_MESSAGE_APP
                text = payload_data if isinstance(payload_data, str) else payload_data.get('text', '')
                packet.decoded.payload = text.encode('utf-8')

            elif msg_type == 'sendposition':
                packet.decoded.portnum = portnums_pb2.PortNum.POSITION_APP
                pos = mesh_pb2.Position()
                # Prefer raw latitude_i/longitude_i; fall back to decimal.
                if 'latitude_i' in payload_data:
                    pos.latitude_i = int(payload_data['latitude_i'])
                elif 'latitude' in payload_data:
                    pos.latitude_i = int(payload_data['latitude'] * 1e7)
                if 'longitude_i' in payload_data:
                    pos.longitude_i = int(payload_data['longitude_i'])
                elif 'longitude' in payload_data:
                    pos.longitude_i = int(payload_data['longitude'] * 1e7)
                if 'altitude' in payload_data:
                    pos.altitude = int(payload_data['altitude'])
                if 'time' in payload_data:
                    pos.time = int(payload_data['time'])
                packet.decoded.payload = pos.SerializeToString()
            else:
                logger.warning(f"Unknown message type for downlink: {msg_type}")
                return

            envelope = mqtt_pb2.ServiceEnvelope()
            envelope.packet.CopyFrom(packet)
            envelope.channel_id = json_data.get('channel_id', channel_name)
            envelope.gateway_id = json_data.get('gateway_id', '')

            if self.get_candidate_keys(channel_name):
                self.encrypt_packet(envelope.packet, channel_name=channel_name)

            protobuf_topic = f"{prefix}/2/e/{channel_name}/{envelope.gateway_id}"
            client.publish(protobuf_topic, envelope.SerializeToString())
            logger.info(f"JSON->Protobuf: {msg.topic} -> {protobuf_topic}")

        except Exception as e:
            logger.error(f"Error converting JSON to Protobuf: {e}")

    def handle_protobuf_to_json(self, client, msg):
        try:
            if '/2/e/' not in msg.topic:
                return

            prefix, suffix = msg.topic.split('/2/e/', 1)
            suffix_parts = [p for p in suffix.split('/') if p]
            if len(suffix_parts) < 2:
                return

            channel = suffix_parts[0]
            user_id = suffix_parts[1]

            envelope = mqtt_pb2.ServiceEnvelope()
            envelope.ParseFromString(msg.payload)

            json_data = None
            if envelope.packet.HasField('decoded'):
                json_data = self.convert_to_json(envelope)
            elif envelope.packet.HasField('encrypted'):
                for key in self.get_candidate_keys(channel):
                    envelope.packet.ClearField('decoded')
                    if self.decrypt_packet(envelope.packet, channel_name=channel, key_override=key):
                        json_data = self.convert_to_json(envelope)
                        if json_data:
                            break

            if json_data:
                json_topic = f"{prefix}/2/json/{channel}/{user_id}"
                # sort_keys matches the firmware's std::map (alphabetical) order.
                client.publish(json_topic, json.dumps(json_data, separators=(',', ':'), sort_keys=True))
                logger.debug(f"Protobuf->JSON: {msg.topic} -> {json_topic} (type={json_data.get('type')}, from={json_data.get('from')})")
        except Exception as e:
            logger.error(f"Error converting Protobuf to JSON: {e}")

    @staticmethod
    def hops_away(packet):
        # Firmware getHopsAway(): -1 (unknown) unless hop_start is set and not exceeded.
        if packet.hop_start != 0 and packet.hop_limit <= packet.hop_start:
            return packet.hop_start - packet.hop_limit
        return -1

    def convert_to_json(self, envelope):
        packet = envelope.packet
        if not packet.HasField('decoded'):
            return None

        decoded = packet.decoded
        portnum = decoded.portnum

        json_obj = {
            "id": packet.id,
            "timestamp": packet.rx_time if packet.rx_time > 0 else 0,
            "to": packet.to,
            "from": getattr(packet, 'from'),
            "channel": packet.channel,
            "sender": envelope.gateway_id if envelope.gateway_id else f"!{getattr(packet, 'from'):08x}"
        }

        payload = None
        if portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
            json_obj["type"] = "text"
            try:
                text = decoded.payload.decode('utf-8')
            except UnicodeDecodeError:
                return None
            # A JSON text payload passes through; otherwise wrap as {"text": ...}.
            try:
                parsed = json.loads(text)
                payload = parsed if isinstance(parsed, dict) else {"text": text}
            except (json.JSONDecodeError, ValueError):
                payload = {"text": text}
        elif portnum == portnums_pb2.PortNum.POSITION_APP:
            json_obj["type"] = "position"
            payload = self.convert_position(decoded)
        elif portnum == portnums_pb2.PortNum.NODEINFO_APP:
            json_obj["type"] = "nodeinfo"
            payload = self.convert_nodeinfo(decoded)
        elif portnum == portnums_pb2.PortNum.TELEMETRY_APP:
            json_obj["type"] = "telemetry"
            payload = self.convert_telemetry(decoded)
        elif portnum == portnums_pb2.PortNum.WAYPOINT_APP:
            json_obj["type"] = "waypoint"
            payload = self.convert_waypoint(decoded)
        elif portnum == portnums_pb2.PortNum.NEIGHBORINFO_APP:
            json_obj["type"] = "neighborinfo"
            payload = self.convert_neighborinfo(decoded)
        elif portnum == portnums_pb2.PortNum.TRACEROUTE_APP:
            # Firmware only serializes the traceroute reply (request_id set).
            if decoded.request_id:
                json_obj["type"] = "traceroute"
                payload = self.convert_traceroute(packet, decoded)
        elif portnum == portnums_pb2.PortNum.DETECTION_SENSOR_APP:
            json_obj["type"] = "detection"
            payload = {"text": decoded.payload.decode('utf-8', errors='ignore')}
        elif portnum == portnums_pb2.PortNum.PAXCOUNTER_APP:
            json_obj["type"] = "paxcounter"
            payload = self.convert_paxcounter(decoded)
        elif portnum == portnums_pb2.PortNum.REMOTE_HARDWARE_APP:
            payload = self.convert_remotehardware(decoded, json_obj)

        # Radio metadata, gated exactly as the firmware gates it.
        if packet.rx_rssi != 0:
            json_obj["rssi"] = packet.rx_rssi
        if packet.rx_snr != 0:
            json_obj["snr"] = packet.rx_snr
        hops = self.hops_away(packet)
        if hops >= 0:
            json_obj["hops_away"] = hops
            json_obj["hop_start"] = packet.hop_start

        if payload is not None and json_obj.get("type"):
            json_obj["payload"] = payload
            return json_obj
        return None

    def convert_position(self, decoded):
        # Raw latitude_i/longitude_i; optional fields gated on non-zero like the firmware.
        try:
            pos = mesh_pb2.Position()
            pos.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(pos):
                return None
            result = {}
            if pos.time:
                result["time"] = pos.time
            if pos.timestamp:
                result["timestamp"] = pos.timestamp
            result["latitude_i"] = pos.latitude_i
            result["longitude_i"] = pos.longitude_i
            if pos.altitude:
                result["altitude"] = pos.altitude
            if pos.ground_speed:
                result["ground_speed"] = pos.ground_speed
            if pos.ground_track:
                result["ground_track"] = pos.ground_track
            if pos.sats_in_view:
                result["sats_in_view"] = pos.sats_in_view
            if pos.PDOP:
                result["PDOP"] = pos.PDOP
            if pos.HDOP:
                result["HDOP"] = pos.HDOP
            if pos.VDOP:
                result["VDOP"] = pos.VDOP
            if pos.precision_bits:
                result["precision_bits"] = pos.precision_bits
            return result
        except Exception as e:
            logger.debug(f"Error decoding position: {e}")
            return None

    def convert_nodeinfo(self, decoded):
        try:
            user = mesh_pb2.User()
            user.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(user):
                return None
            return {
                "id": user.id,
                "longname": user.long_name,
                "shortname": user.short_name,
                "hardware": int(user.hw_model),
                "role": int(user.role)
            }
        except Exception as e:
            logger.debug(f"Error decoding nodeinfo: {e}")
            return None

    def convert_telemetry(self, decoded):
        try:
            telemetry = telemetry_pb2.Telemetry()
            telemetry.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(telemetry):
                return None
        except Exception as e:
            logger.debug(f"Error decoding telemetry: {e}")
            return None

        result = {}

        if telemetry.HasField('device_metrics'):
            dm = telemetry.device_metrics
            # battery_level is presence-gated; the rest are always emitted.
            if dm.HasField('battery_level'):
                result["battery_level"] = dm.battery_level
            result["voltage"] = dm.voltage
            result["channel_utilization"] = dm.channel_utilization
            result["air_util_tx"] = dm.air_util_tx
            result["uptime_seconds"] = dm.uptime_seconds
        elif telemetry.HasField('environment_metrics'):
            em = telemetry.environment_metrics
            if em.HasField('temperature'):
                result["temperature"] = em.temperature
            if em.HasField('relative_humidity'):
                result["relative_humidity"] = em.relative_humidity
            if em.HasField('barometric_pressure'):
                result["barometric_pressure"] = em.barometric_pressure
            if em.HasField('gas_resistance'):
                result["gas_resistance"] = em.gas_resistance
            if em.HasField('voltage'):
                result["voltage"] = em.voltage
            if em.HasField('current'):
                result["current"] = em.current
            if em.HasField('lux'):
                result["lux"] = em.lux
            if em.HasField('white_lux'):
                result["white_lux"] = em.white_lux
            if em.HasField('iaq'):
                result["iaq"] = em.iaq
            if em.HasField('distance'):
                result["distance"] = em.distance
            if em.HasField('wind_speed'):
                result["wind_speed"] = em.wind_speed
            if em.HasField('wind_direction'):
                result["wind_direction"] = em.wind_direction
            if em.HasField('wind_gust'):
                result["wind_gust"] = em.wind_gust
            if em.HasField('wind_lull'):
                result["wind_lull"] = em.wind_lull
            if em.HasField('radiation'):
                result["radiation"] = em.radiation
            if em.HasField('ir_lux'):
                result["ir_lux"] = em.ir_lux
            if em.HasField('uv_lux'):
                result["uv_lux"] = em.uv_lux
            if em.HasField('weight'):
                result["weight"] = em.weight
            if em.HasField('rainfall_1h'):
                result["rainfall_1h"] = em.rainfall_1h
            if em.HasField('rainfall_24h'):
                result["rainfall_24h"] = em.rainfall_24h
            if em.HasField('soil_moisture'):
                result["soil_moisture"] = em.soil_moisture
            if em.HasField('soil_temperature'):
                result["soil_temperature"] = em.soil_temperature
        elif telemetry.HasField('power_metrics'):
            pm = telemetry.power_metrics
            if pm.HasField('ch1_voltage'):
                result["voltage_ch1"] = pm.ch1_voltage
            if pm.HasField('ch1_current'):
                result["current_ch1"] = pm.ch1_current
            if pm.HasField('ch2_voltage'):
                result["voltage_ch2"] = pm.ch2_voltage
            if pm.HasField('ch2_current'):
                result["current_ch2"] = pm.ch2_current
            if pm.HasField('ch3_voltage'):
                result["voltage_ch3"] = pm.ch3_voltage
            if pm.HasField('ch3_current'):
                result["current_ch3"] = pm.ch3_current
        elif telemetry.HasField('air_quality_metrics'):
            aq = telemetry.air_quality_metrics
            if aq.HasField('pm10_standard'):
                result["pm10"] = aq.pm10_standard
            if aq.HasField('pm25_standard'):
                result["pm25"] = aq.pm25_standard
            if aq.HasField('pm100_standard'):
                result["pm100"] = aq.pm100_standard
            if aq.HasField('pm10_environmental'):
                result["pm10_e"] = aq.pm10_environmental
            if aq.HasField('pm25_environmental'):
                result["pm25_e"] = aq.pm25_environmental
            if aq.HasField('pm100_environmental'):
                result["pm100_e"] = aq.pm100_environmental
            if aq.HasField('particles_03um'):
                result["particles_03um"] = aq.particles_03um
            if aq.HasField('particles_05um'):
                result["particles_05um"] = aq.particles_05um
            if aq.HasField('particles_10um'):
                result["particles_10um"] = aq.particles_10um
            if aq.HasField('particles_25um'):
                result["particles_25um"] = aq.particles_25um
            if aq.HasField('particles_50um'):
                result["particles_50um"] = aq.particles_50um
            if aq.HasField('particles_100um'):
                result["particles_100um"] = aq.particles_100um
            if aq.HasField('co2'):
                result["co2"] = aq.co2
            if aq.HasField('co2_temperature'):
                result["co2_temperature"] = aq.co2_temperature
            if aq.HasField('co2_humidity'):
                result["co2_humidity"] = aq.co2_humidity
        elif telemetry.HasField('local_stats'):
            ls = telemetry.local_stats
            result["uptime_seconds"] = ls.uptime_seconds
            result["channel_utilization"] = ls.channel_utilization
            result["air_util_tx"] = ls.air_util_tx
            result["num_packets_tx"] = ls.num_packets_tx
            result["num_packets_rx"] = ls.num_packets_rx
            result["num_packets_rx_bad"] = ls.num_packets_rx_bad
            result["num_online_nodes"] = ls.num_online_nodes
            result["num_total_nodes"] = ls.num_total_nodes
            result["num_rx_dupe"] = ls.num_rx_dupe
            result["num_tx_relay"] = ls.num_tx_relay
            result["num_tx_relay_canceled"] = ls.num_tx_relay_canceled
        elif telemetry.HasField('health_metrics'):
            hm = telemetry.health_metrics
            if hm.HasField('heart_bpm'):
                result["heart_bpm"] = hm.heart_bpm
            if hm.HasField('spO2'):
                result["spO2"] = hm.spO2
            if hm.HasField('temperature'):
                result["temperature"] = hm.temperature
        elif telemetry.HasField('host_metrics'):
            ho = telemetry.host_metrics
            result["uptime_seconds"] = ho.uptime_seconds
            result["freemem_bytes"] = ho.freemem_bytes
            result["diskfree1_bytes"] = ho.diskfree1_bytes
            if ho.HasField('diskfree2_bytes'):
                result["diskfree2_bytes"] = ho.diskfree2_bytes
            if ho.HasField('diskfree3_bytes'):
                result["diskfree3_bytes"] = ho.diskfree3_bytes
            result["load1"] = ho.load1
            result["load5"] = ho.load5
            result["load15"] = ho.load15
            if ho.HasField('user_string'):
                result["user_string"] = ho.user_string
        else:
            return None

        return result

    def convert_waypoint(self, decoded):
        try:
            waypoint = mesh_pb2.Waypoint()
            waypoint.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(waypoint):
                return None
            # Firmware emits raw latitude_i/longitude_i plus the lifecycle fields.
            return {
                "id": waypoint.id,
                "name": waypoint.name,
                "description": waypoint.description,
                "expire": waypoint.expire,
                "locked_to": waypoint.locked_to,
                "latitude_i": waypoint.latitude_i,
                "longitude_i": waypoint.longitude_i
            }
        except Exception as e:
            logger.debug(f"Error decoding waypoint: {e}")
            return None

    def convert_neighborinfo(self, decoded):
        try:
            neighbor_info = mesh_pb2.NeighborInfo()
            neighbor_info.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(neighbor_info):
                return None
            return {
                "node_id": neighbor_info.node_id,
                "node_broadcast_interval_secs": neighbor_info.node_broadcast_interval_secs,
                "last_sent_by_id": neighbor_info.last_sent_by_id,
                "neighbors_count": len(neighbor_info.neighbors),
                "neighbors": [{"node_id": n.node_id, "snr": int(n.snr)} for n in neighbor_info.neighbors]
            }
        except Exception as e:
            logger.debug(f"Error decoding neighborinfo: {e}")
            return None

    def convert_traceroute(self, packet, decoded):
        # No NodeDB here, so hops render as "!aabbccdd" ids (firmware uses long-names).
        # SNR is quarter-dB in the protobuf, hence /4.
        try:
            route_disc = mesh_pb2.RouteDiscovery()
            route_disc.ParseFromString(decoded.payload)
            if not has_no_unknown_fields(route_disc):
                return None

            def node_name(num):
                return f"!{num & 0xffffffff:08x}"

            route = [node_name(packet.to)]
            route += [node_name(n) for n in route_disc.route]
            route.append(node_name(getattr(packet, 'from')))

            route_back = [node_name(getattr(packet, 'from'))]
            route_back += [node_name(n) for n in route_disc.route_back]
            route_back.append(node_name(packet.to))

            return {
                "route": route,
                "route_back": route_back,
                "snr_back": [s / 4 for s in route_disc.snr_back],
                "snr_towards": [s / 4 for s in route_disc.snr_towards]
            }
        except Exception as e:
            logger.error(f"Error decoding traceroute: {e}")
            return None

    def convert_paxcounter(self, decoded):
        if paxcount_pb2 is None:
            logger.warning("paxcount_pb2 unavailable; cannot decode paxcounter")
            return None
        try:
            pax = paxcount_pb2.Paxcount()
            pax.ParseFromString(decoded.payload)
            return {
                "wifi_count": pax.wifi,
                "ble_count": pax.ble,
                "uptime": pax.uptime
            }
        except Exception as e:
            logger.error(f"Error decoding paxcounter: {e}")
            return None

    def convert_remotehardware(self, decoded, json_obj):
        # Sets json_obj["type"] itself (gpios_changed / gpios_read_reply).
        if remote_hardware_pb2 is None:
            logger.warning("remote_hardware_pb2 unavailable; cannot decode remote hardware")
            return None
        try:
            hw = remote_hardware_pb2.HardwareMessage()
            hw.ParseFromString(decoded.payload)
            if hw.type == remote_hardware_pb2.HardwareMessage.Type.GPIOS_CHANGED:
                json_obj["type"] = "gpios_changed"
                return {"gpio_value": hw.gpio_value}
            elif hw.type == remote_hardware_pb2.HardwareMessage.Type.READ_GPIOS_REPLY:
                json_obj["type"] = "gpios_read_reply"
                return {"gpio_value": hw.gpio_value, "gpio_mask": hw.gpio_mask}
            return None
        except Exception as e:
            logger.error(f"Error decoding remote hardware: {e}")
            return None

    def start(self):
        logger.info(f"Starting converter for root='{self.root_topic}', region='{self.region}'")
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_forever()


def load_ha_options(path="/data/options.json"):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception as e:
        logger.error(f"Failed to load {path}: {e}")
        return {}


if __name__ == "__main__":
    ha_opts = load_ha_options()

    parser = argparse.ArgumentParser(description='Meshtastic MQTT Protobuf to JSON Converter')
    parser.add_argument('--broker', default=ha_opts.get('broker') or os.getenv('BROKER', 'mqtt.meshtastic.org'), help='MQTT broker address')
    parser.add_argument('--port', type=int, default=int(ha_opts.get('port') or os.getenv('PORT', 1883)), help='MQTT port')
    parser.add_argument('--username', default=ha_opts.get('username') or os.getenv('USERNAME') or None, help='MQTT username')
    parser.add_argument('--password', default=ha_opts.get('password') or os.getenv('PASSWORD') or None, help='MQTT password')
    parser.add_argument('--region', default=ha_opts.get('region') if 'region' in ha_opts else os.getenv('REGION', 'EU_868'), help='Meshtastic region (supports multi-level and MQTT wildcards, e.g. US/AZ/+)')
    parser.add_argument('--root-topic', default=ha_opts.get('root_topic') or os.getenv('ROOT_TOPIC', 'msh'), help='Root topic')
    parser.add_argument('--psk', default=ha_opts.get('psk') or os.getenv('PSK') or None, help='Fallback/default PSK(s) (comma-separated hex, base64, or "default")')
    parser.add_argument('--channel', action='append', default=[], help='Per-channel PSK in NAME:PSK format (can be specified multiple times)')
    parser.add_argument('--debug', action='store_true', default=bool(ha_opts.get('debug') or os.getenv('DEBUG')), help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    channels_cfg = list(ha_opts.get('channels') or [])
    if os.getenv('CHANNELS'):
        for item in os.getenv('CHANNELS').split(','):
            if ':' in item:
                channels_cfg.append(item.strip())
    if args.channel:
        channels_cfg.extend(args.channel)

    converter = MeshtasticConverter(
        args.broker,
        args.port,
        args.username,
        args.password,
        args.region,
        args.root_topic,
        psk=args.psk,
        channels=channels_cfg,
    )

    try:
        converter.start()
    except KeyboardInterrupt:
        logger.info("Stopped")
