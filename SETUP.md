# Setup Guide

## 1. Create secrets.h

```bash
cp secrets.h.example secrets.h
```

Edit `secrets.h` with your values:
- WiFi credentials
- Nostr relay host (e.g., `relay.example.com`)
- Nostr private key (64 hex chars)
- Plant pot d-tag (e.g., `"plant-pot-1"`)
- Relay GPIO pin (default: 4)

## 2. Wire Hardware

**Relay Module:**
- ESP32 GPIO 4 → Relay IN pin (3 pins on one side - usually middle pin)
- ESP32 GND → Relay GND pin
- ESP32 5V → Relay VCC pin

**Screw Terminals (NC, COM, NO):**
- Power Supply (+) → COM
- NO → Pump (+)
- Power Supply (-) → Pump (-)

**Note**: If relay pins are unlabeled, IN is usually the middle pin. Check module docs or test with multimeter.

## 3. Install PlatformIO

```bash
# macOS
brew install platformio

# Or install VS Code extension: PlatformIO IDE
```

## 4. Build & Upload

```bash
pio run -t upload
```

## 5. Monitor Serial Output

```bash
pio device monitor
```

You should see:
- WiFi connection
- Nostr relay connection
- Pubkey printed
- "Ready!" message
- Polling every 30s

## 6. Test

In your web app, create a replaceable event (kind 30000) with:
```json
{
  "kind": 30000,
  "tags": [
    ["d", "plant-pot-1"],
    ["task", "water", "5"]
  ],
  "content": ""
}
```

Device should execute after next poll (max 30s wait).

## NTP Servers

The `configTime()` call syncs system time for Nostr event timestamps (required for event signing). Using Cloudflare's NTP server.

