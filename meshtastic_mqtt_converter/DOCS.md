# Meshtastic MQTT Converter Add-on

Subscribes to Meshtastic Protobuf MQTT topics (`<root_topic>/<region>/2/e/#`), decrypts packets using your configured channel PSKs, and republishes firmware-compatible JSON packets to `<root_topic>/<region>/2/json/<channel>/<gateway_id>`.

## Configuration Options

- **`broker`**: MQTT broker hostname or IP (e.g. `10.0.123.41` or `a0d7b954-emqx`)
- **`port`**: MQTT broker port (default `1883`)
- **`username` / `password`**: MQTT broker credentials
- **`root_topic`**: Root Meshtastic topic (default `msh`)
- **`region`**: Region subpath (supports multi-level paths and `+` wildcards, e.g. `US/AZ/+` or `US/AZ/Tucson`)
- **`psk`**: Optional fallback PSK (`default`, `AQ==`, `base64:...`, or `0x...`)
- **`channels`**: List of `{ name, psk }` mappings for per-channel decryption and downlink encryption
- **`debug`**: Enable verbose debug logging
