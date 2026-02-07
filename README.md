# Plantr

ESP32 IoT device that waters plants based on Nostr replaceable events.

## Nostr Kinds

- **Kind 30000**: Replaceable plant pot event (NIP-33)
- **Kind 30001**: Log event (execution record)

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
- Relay is Active LOW (LOW = ON, HIGH = OFF)

## Setup

1. Copy `secrets.h.example` to `secrets.h`
2. Fill in your values:
   - `WIFI_SSID` / `WIFI_PASS`
   - `NOSTR_RELAY_HOST`
   - `NOSTR_PRIVKEY` (64-char hex)
   - `PLANT_POT_D_TAG` (e.g., "plant-pot-1")
   - `RELAY_PIN` (default: 4)

3. Build and upload: `pio run -t upload`

## Event Structure

**Plant Pot (Kind 30000):**
```json
{
  "kind": 30000,
  "tags": [
    ["d", "plant-pot-1"],
    ["task", "water", "30"]
  ],
  "content": ""
}
```

**Log (Kind 30001):**
```json
{
  "kind": 30001,
  "tags": [
    ["a", "30000:<pubkey>:plant-pot-1"],
    ["task", "water", "30"]
  ],
  "content": ""
}
```

Device polls every 30s, executes water tasks, publishes log events.
