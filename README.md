# Plantr

ESP32 IoT device that waters plants based on Nostr replaceable events.

## Nostr Kinds

- **Kind 34419**: Replaceable plant pot event (NIP-33)
- **Kind 4171**: Activity log event (regular event, not replaceable)

## Wiring

**Relay Module (3 pins on one side, 3 screw terminals on other):**

```
ESP32 GPIO 4 ──────▶ Relay IN pin (middle pin, or check module)
ESP32 GND ─────────▶ Relay GND pin
ESP32 5V ──────────▶ Relay VCC pin

Power Supply (+) ───▶ Relay COM (screw terminal)
Relay NO ──────────▶ Pump (+)
Power Supply (-) ───▶ Pump (-)
```

**Note**: 
- The 3 pins are usually: VCC, GND, IN (signal). If unlabeled, check module docs or test with multimeter.
- NC = Normally Closed (unused)
- COM = Common (power input)
- NO = Normally Open (connects to COM when relay activates)
- Relay is Active HIGH (HIGH = ON, LOW = OFF)

## Setup

1. Copy `secrets.h.example` to `secrets.h`
2. Fill in your values:
   - `WIFI_SSID` / `WIFI_PASS`
   - `NOSTR_RELAY_HOST`
   - `NOSTR_PRIVKEY` (64-char hex, device's own keypair - currently unused)
   - `PLANT_POT_PRIVKEY` (64-char hex, plant pot's private key for updating events)
   - `PLANT_POT_D_TAG` (e.g., "test-pot-4")
   - `RELAY_PIN` (default: 4)

3. Build and upload: `pio run -t upload`

## Event Structure

**Plant Pot (Kind 34419) - Replaceable Event:**
```json
{
  "kind": 34419,
  "pubkey": "<plant-pot-pubkey>",
  "tags": [
    ["d", "test-pot-4"],
    ["name", "Monstera"],
    ["task", "water", "30"]
  ],
  "content": ""
}
```

**Activity Log (Kind 4171) - Regular Event:**
```json
{
  "kind": 4171,
  "pubkey": "<iot-device-pubkey>",
  "tags": [
    ["a", "34419:<plant-pot-pubkey>:test-pot-4"],
    ["e", "<plant-pot-event-id>"],
    ["task", "water", "30"]
  ],
  "content": ""
}
```

**Activity Log Tags:**
- `["a", "..."]`: References the plant pot replaceable event using NIP-33 format (`kind:pubkey:d-tag`)
- `["e", "..."]`: References the specific plant pot event ID that triggered this log entry
- `["task", "water", "30"]`: The task that was executed (type and value)

Device polls every 15s, executes water tasks, publishes activity logs, and updates the replaceable event by removing completed tasks.
