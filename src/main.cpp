#include <Arduino.h>

#ifndef SECRETS_FILE
  #error "SECRETS_FILE must be defined! Use -DSECRETS_FILE=\"secrets.h\" in platformio.ini"
#endif
#include SECRETS_FILE

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include <time.h>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <mbedtls/sha256.h>
#include "uECC.h"

// Nostr kinds
#define KIND_PLANT_POT 34419  // Replaceable plant pot event (NIP-33)
#define KIND_ACTIVITY_LOG 4171  // Activity log (regular event, not replaceable)

// secp256k1 curve order
static const uint8_t SECP256K1_ORDER[32] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
  0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
  0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static const uint8_t TAG_CHALLENGE[32] = {
  0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32,
  0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
  0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f,
  0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c
};
static const uint8_t TAG_NONCE[32] = {
  0x07, 0x49, 0x77, 0x34, 0xa7, 0x9b, 0xcb, 0x35,
  0x5b, 0x9b, 0x8c, 0x7d, 0x03, 0x4f, 0x12, 0x1c,
  0xf4, 0x34, 0xd7, 0x3a, 0xf6, 0x39, 0x7b, 0x96,
  0xb8, 0x0a, 0xab, 0x80, 0x51, 0x85, 0x45, 0x69
};
static const uint8_t TAG_AUX[32] = {
  0xf1, 0xef, 0x4e, 0x5e, 0xc0, 0x63, 0xca, 0xda,
  0xf7, 0xef, 0xf4, 0xb9, 0x8e, 0x3b, 0x67, 0xc8,
  0xa7, 0x90, 0xae, 0xfe, 0x0f, 0x05, 0xfc, 0x7a,
  0x5f, 0x21, 0xa9, 0x93, 0x01, 0x6c, 0x3a, 0xba
};

char ssid[] = WIFI_SSID;
char pass[] = WIFI_PASS;
const char* nostrRelayHost = NOSTR_RELAY_HOST;
const uint16_t nostrRelayPort = 443;
const char* nostrRelayPath = "/";
const char* nostrPrivateKeyHex = NOSTR_PRIVKEY;
const char* plantPotPrivKeyHex = PLANT_POT_PRIVKEY;
const char* plantPotDTag = PLANT_POT_D_TAG;
const int relayPin = RELAY_PIN;
const unsigned long POLL_INTERVAL = 15000;  // 15 seconds
const unsigned long MAX_WATER_SECONDS = 300;  // Safety limit

WebSocketsClient webSocket;
bool wsConnected = false;
String nostrPubkey = "";
uint8_t privKeyBytes[32];
uint8_t pubKeyBytes[32];
String plantPotPubkey = "";
uint8_t plantPotPrivKeyBytes[32];

// Event processing queue
bool pendingEvent = false;
String pendingEventJson = "";
String lastProcessedEventId = "";  // Track to avoid reprocessing same event (resets on boot)

// Forward declarations
void connectWiFi();
void setupNostrRelay();
void webSocketEvent(WStype_t type, uint8_t* payload, size_t length);
void subscribeToPlantPot();
void processPlantPotEvent(const String& eventJson);
void executeWaterTask(int seconds);
void updateReplaceableEvent(const String& filteredTagsJson, const String& content);
void publishActivityLog(const String& taskType, int taskValue, const String& plantPotEventId);
void derivePubkey();
void derivePlantPotPubkey();
String createPlantPotEvent(const String& tags, const String& content);
String createNostrEvent(int kind, const String& tags, const String& content);
String bytesToHex(uint8_t* bytes, int len);
void hexToBytes(const char* hex, uint8_t* bytes, int len);
void sha256Raw(const uint8_t* data, size_t len, uint8_t* out);
void taggedHash(const uint8_t* tag, const uint8_t* data, size_t len, uint8_t* out);
bool schnorrSign(const uint8_t* privkey, const uint8_t* msg, uint8_t* sig);
String createNostrEvent(int kind, const String& tags, const String& content);

// Big number operations
int bn_compare(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 32; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

void bn_sub(const uint8_t* a, const uint8_t* b, uint8_t* result) {
  int16_t borrow = 0;
  for (int i = 31; i >= 0; i--) {
    int16_t diff = (int16_t)a[i] - (int16_t)b[i] - borrow;
    if (diff < 0) {
      diff += 256;
      borrow = 1;
    } else {
      borrow = 0;
    }
    result[i] = (uint8_t)diff;
  }
}

void bn_add_mod(const uint8_t* a, const uint8_t* b, const uint8_t* n, uint8_t* result) {
  uint8_t temp[33] = {0};
  uint16_t carry = 0;
  for (int i = 31; i >= 0; i--) {
    uint16_t sum = (uint16_t)a[i] + (uint16_t)b[i] + carry;
    temp[i + 1] = (uint8_t)(sum & 0xFF);
    carry = sum >> 8;
  }
  temp[0] = carry;
  uint8_t* ptr = temp + 1;
  if (temp[0] || bn_compare(ptr, n) >= 0) {
    bn_sub(ptr, n, ptr);
  }
  memcpy(result, ptr, 32);
}

void bn_mod(uint8_t* a, const uint8_t* n) {
  while (bn_compare(a, n) >= 0) {
    bn_sub(a, n, a);
  }
}

void bn_mul_mod(const uint8_t* a, const uint8_t* b, const uint8_t* n, uint8_t* result) {
  uint8_t acc[32] = {0};
  uint8_t temp[32];
  memcpy(temp, a, 32);
  for (int i = 31; i >= 0; i--) {
    for (int bit = 0; bit < 8; bit++) {
      if ((b[i] >> bit) & 1) {
        bn_add_mod(acc, temp, n, acc);
      }
      bn_add_mod(temp, temp, n, temp);
    }
  }
  memcpy(result, acc, 32);
}

static int RNG(uint8_t *dest, unsigned size) {
  while (size--) *dest++ = (uint8_t)random(256);
  return 1;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  randomSeed(analogRead(0) ^ micros());
  uECC_set_rng(&RNG);
  
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
  
  pinMode(relayPin, OUTPUT);
  digitalWrite(relayPin, LOW);   // Relay OFF (active HIGH - inverted logic)
  
  Serial.println("\n=== Plantr ESP32 ===");
  
  connectWiFi();
  
  configTime(0, 0, "time.cloudflare.com");
  Serial.print("Time sync");
  time_t now = time(nullptr);
  while (now < 1700000000) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println(" OK");
  
  derivePubkey();
  derivePlantPotPubkey();
  Serial.printf("Using d-tag: %s\n", plantPotDTag);
  setupNostrRelay();
  
  delay(2000);
  // Wait for initial connection and subscribe
  unsigned long timeout = millis();
  while (!wsConnected && (millis() - timeout < 10000)) {
    webSocket.loop();
    delay(100);
  }
  if (wsConnected) {
    delay(500);
    subscribeToPlantPot();
  }
  
  Serial.println("Ready!");
}

void loop() {
  webSocket.loop();
  
  // Process pending events (avoid nested WebSocket operations)
  if (pendingEvent) {
    pendingEvent = false;
    String eventJson = pendingEventJson;
    pendingEventJson = "";  // Clear it
    processPlantPotEvent(eventJson);
  }
  
  static unsigned long lastPoll = 0;
  unsigned long now = millis();
  
  if (now - lastPoll > POLL_INTERVAL) {
    if (wsConnected) {
      subscribeToPlantPot();
    }
    lastPoll = now;
  }
  
  delay(10);
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, pass);
  Serial.print("WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(" OK");
  Serial.println(WiFi.localIP());
}

void setupNostrRelay() {
  webSocket.beginSSL(nostrRelayHost, nostrRelayPort, nostrRelayPath);
  webSocket.onEvent(webSocketEvent);
  webSocket.setReconnectInterval(5000);
  webSocket.enableHeartbeat(15000, 3000, 2);
}

void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch(type) {
    case WStype_DISCONNECTED:
      wsConnected = false;
      Serial.println("[WS] Disconnected");
      break;
    case WStype_CONNECTED:
      wsConnected = true;
      Serial.println("[WS] Connected");
      // Don't auto-subscribe on reconnect - let polling interval handle it
      // This prevents immediate event spam on reconnect
      break;
    case WStype_TEXT: {
      String msg = String((char*)payload);
      
      // Filter out EOSE messages (too noisy)
      if (msg.indexOf("\"EOSE\"") >= 0) {
        // Silently ignore EOSE messages
        break;
      }
      
      Serial.println("[WS] " + msg);
      
      // Parse EVENT messages
      if (msg.startsWith("[\"EVENT\",")) {
        StaticJsonDocument<2048> doc;
        DeserializationError error = deserializeJson(doc, msg);
        if (!error && doc[0] == "EVENT") {
          // Event is at index 2: ["EVENT", "subscription-id", {event}]
          JsonObject event = doc[2];
          if (event["kind"] == KIND_PLANT_POT) {
            String eventId = event["id"].as<String>();
            // Skip if we've already processed this event
            if (eventId == lastProcessedEventId) {
              Serial.println("Skipping already processed event: " + eventId);
              break;
            }
            String eventJson;
            serializeJson(event, eventJson);
            // Queue for processing in main loop (avoid nested WebSocket ops)
            pendingEventJson = eventJson;
            pendingEvent = true;
          }
        }
      }
      break;
    }
    default:
      break;
  }
}

void subscribeToPlantPot() {
  // Close any existing subscription first
  String closeSub = "[\"CLOSE\",\"plantr-sub\"]";
  webSocket.sendTXT(closeSub);
  delay(100);
  
  Serial.printf("Subscribing to plant pot: pubkey=%s, d-tag=%s\n", plantPotPubkey.c_str(), plantPotDTag);
  
  String filter = "[";
  filter += "\"REQ\",";
  filter += "\"plantr-sub\",";
  filter += "{";
  filter += "\"kinds\":[" + String(KIND_PLANT_POT) + "],";
  filter += "\"authors\":[\"" + plantPotPubkey + "\"],";
  filter += "\"#d\":[\"" + String(plantPotDTag) + "\"]";
  filter += "}";
  filter += "]";
  
  Serial.println("Subscription filter: " + filter);
  webSocket.sendTXT(filter);
}

void processPlantPotEvent(const String& eventJson) {
  Serial.println("\n=== Processing plant pot event ===");
  
  // Parse event
  Serial.println("Parsing event JSON...");
  StaticJsonDocument<2048> doc;
  DeserializationError error = deserializeJson(doc, eventJson);
  if (error) {
    Serial.print("JSON parse error: ");
    Serial.println(error.c_str());
    return;
  }
  
  // Track event ID to avoid reprocessing
  String eventId = doc["id"].as<String>();
  Serial.printf("Processing event ID: %s\n", eventId.c_str());
  Serial.printf("Last processed event ID: %s\n", lastProcessedEventId.length() > 0 ? lastProcessedEventId.c_str() : "(none)");
  
  // Double-check we haven't already processed this (shouldn't happen due to check in webSocketEvent, but safety check)
  if (eventId == lastProcessedEventId) {
    Serial.println("WARNING: Attempted to process already-processed event! Skipping.");
    return;
  }
  
  lastProcessedEventId = eventId;
  
  JsonArray tags = doc["tags"];
  if (!tags) {
    Serial.println("No tags found");
    return;
  }
  
  Serial.printf("Found %d tags\n", tags.size());
  
  // Collect tasks to execute
  bool hasTasks = false;
  int taskSeconds = 0;
  
  for (JsonArray tag : tags) {
    Serial.printf("Checking tag, size: %d\n", tag.size());
    if (tag.size() >= 3) {
      String tag0 = tag[0].as<String>();
      String tag1 = tag[1].as<String>();
      Serial.printf("  Tag[0]=%s, Tag[1]=%s\n", tag0.c_str(), tag1.c_str());
      
      if (tag0 == "task" && tag1 == "water") {
        taskSeconds = tag[2].as<int>();
        Serial.printf("  Found water task: %d seconds\n", taskSeconds);
        if (taskSeconds > 0 && taskSeconds <= MAX_WATER_SECONDS) {
          hasTasks = true;
        } else {
          Serial.printf("  Invalid seconds: %d (max: %lu)\n", taskSeconds, MAX_WATER_SECONDS);
        }
      }
    }
  }
  
  // Extract filtered tags and content BEFORE executing tasks (so doc can be destroyed)
  String filteredTagsJson = "";
  String originalContent = doc["content"].as<String>();
  if (hasTasks) {
    Serial.println("Extracting filtered tags (removing water tasks)...");
    StaticJsonDocument<1024> newTagsDoc;
    JsonArray newTagsArray = newTagsDoc.to<JsonArray>();
    int keptTags = 0;
    
    for (JsonArray tag : tags) {
      // Skip ONLY water tasks (they'll be executed)
      if (tag.size() >= 3 && tag[0] == "task" && tag[1] == "water") {
        Serial.println("  Skipping water task tag");
        continue;
      }
      // Keep ALL other tags (d-tag, name, p-tag, client, etc.)
      Serial.printf("  Keeping tag: [");
      JsonArray newTag = newTagsArray.createNestedArray();
      for (int i = 0; i < tag.size(); i++) {
        String tagValue = tag[i].as<String>();
        newTag.add(tagValue);
        if (i > 0) Serial.print(", ");
        Serial.print("\"" + tagValue + "\"");
      }
      Serial.println("]");
      keptTags++;
    }
    serializeJson(newTagsArray, filteredTagsJson);
    Serial.printf("Extracted %d tags (water task removed)\n", keptTags);
  }
  
  // Now doc goes out of scope - stack is cleaner
  
  // Execute tasks
  if (hasTasks) {
    // Only disconnect if we have tasks to execute
    Serial.println("Disconnecting WebSocket for task execution...");
    webSocket.disconnect();
    delay(500);
    
    Serial.printf("\n=== Executing water task: %d seconds ===\n", taskSeconds);
    executeWaterTask(taskSeconds);
    Serial.println("Task execution complete");
    
    // Reconnect WebSocket before updating event
    Serial.println("Reconnecting WebSocket for event update...");
    setupNostrRelay();
    delay(1000);
    
    // Wait for connection
    unsigned long timeout = millis();
    while (!wsConnected && (millis() - timeout < 5000)) {
      webSocket.loop();
      delay(100);
    }
    
    if (wsConnected) {
      Serial.println("\n=== Updating replaceable event ===");
      updateReplaceableEvent(filteredTagsJson, originalContent);
      
      // Publish activity log
      Serial.println("Publishing activity log...");
      publishActivityLog("water", taskSeconds, eventId);
      
      // Reset processed event ID so we can process the updated event
      // (which will have a new ID since it's a new replaceable event)
      lastProcessedEventId = "";
      
      // Wait a bit for the relay to propagate the update before resubscribing
      delay(2000);
    } else {
      Serial.println("FAILED: Could not reconnect WebSocket to update event");
    }
  } else {
    Serial.println("No valid tasks found - no action needed");
  }
  
  Serial.println("=== Done processing ===\n");
}

void executeWaterTask(int seconds) {
  Serial.println("Turning pump ON...");
  digitalWrite(relayPin, HIGH);  // Relay ON (active HIGH - inverted logic)
  Serial.printf("Pump ON, waiting %d seconds\n", seconds);
  
  // Simple blocking delay (WebSocket is disconnected)
  delay(seconds * 1000);
  
  Serial.println("Turning pump OFF...");
  digitalWrite(relayPin, LOW);   // Relay OFF
  Serial.println("Pump OFF");
}

void updateReplaceableEvent(const String& filteredTagsJson, const String& content) {
  Serial.println("Step 1: Creating plant pot event with filtered tags...");
  String event = createPlantPotEvent(filteredTagsJson, content);
  if (event.length() == 0) {
    Serial.println("Step 1: FAILED - createPlantPotEvent returned empty");
    return;
  }
  Serial.printf("Step 1: OK, event length: %d\n", event.length());
  
  Serial.println("Step 2: Sending updated event...");
  String msg = "[\"EVENT\"," + event + "]";
  webSocket.sendTXT(msg);
  Serial.println("Step 2: OK - Replaceable event updated (tasks removed)");
}

void publishActivityLog(const String& taskType, int taskValue, const String& plantPotEventId) {
  // Build tags for activity log
  // "a" tag references the plant pot replaceable event (kind:pubkey:d-tag format)
  String aTag = String(KIND_PLANT_POT) + ":" + plantPotPubkey + ":" + String(plantPotDTag);
  String tags = "[";
  tags += "[\"a\",\"" + aTag + "\"],";
  tags += "[\"e\",\"" + plantPotEventId + "\"],";  // Reference to the specific plant pot event that triggered this
  tags += "[\"task\",\"" + taskType + "\",\"" + String(taskValue) + "\"]";
  tags += "]";
  
  // Create and sign the log event (signed by IoT device's own keypair)
  String event = createNostrEvent(KIND_ACTIVITY_LOG, tags, "");
  if (event.length() == 0) {
    Serial.println("FAILED: createNostrEvent returned empty for activity log");
    return;
  }
  
  // Send to relay
  String msg = "[\"EVENT\"," + event + "]";
  webSocket.sendTXT(msg);
  Serial.println("Activity log published");
}

String createNostrEvent(int kind, const String& tags, const String& content) {
  unsigned long createdAt = (unsigned long)time(nullptr);
  
  String canonical = "[0,\"" + nostrPubkey + "\"," + String(createdAt) + "," + String(kind) + "," + tags + ",\"" + content + "\"]";
  
  uint8_t eventIdBytes[32];
  sha256Raw((const uint8_t*)canonical.c_str(), canonical.length(), eventIdBytes);
  String eventId = bytesToHex(eventIdBytes, 32);
  
  uint8_t sig[64];
  if (!schnorrSign(privKeyBytes, eventIdBytes, sig)) {
    Serial.println("Sign failed!");
    return "";
  }
  String signature = bytesToHex(sig, 64);
  
  String event = "{\"id\":\"" + eventId + "\",";
  event += "\"pubkey\":\"" + nostrPubkey + "\",";
  event += "\"created_at\":" + String(createdAt) + ",";
  event += "\"kind\":" + String(kind) + ",";
  event += "\"tags\":" + tags + ",";
  event += "\"content\":\"" + content + "\",";
  event += "\"sig\":\"" + signature + "\"}";
  
  return event;
}

String createPlantPotEvent(const String& tags, const String& content) {
  unsigned long createdAt = (unsigned long)time(nullptr);
  
  String canonical = "[0,\"" + plantPotPubkey + "\"," + String(createdAt) + "," + String(KIND_PLANT_POT) + "," + tags + ",\"" + content + "\"]";
  
  uint8_t eventIdBytes[32];
  sha256Raw((const uint8_t*)canonical.c_str(), canonical.length(), eventIdBytes);
  String eventId = bytesToHex(eventIdBytes, 32);
  
  uint8_t sig[64];
  if (!schnorrSign(plantPotPrivKeyBytes, eventIdBytes, sig)) {
    Serial.println("Plant pot sign failed!");
    return "";
  }
  String signature = bytesToHex(sig, 64);
  
  String event = "{\"id\":\"" + eventId + "\",";
  event += "\"pubkey\":\"" + plantPotPubkey + "\",";
  event += "\"created_at\":" + String(createdAt) + ",";
  event += "\"kind\":" + String(KIND_PLANT_POT) + ",";
  event += "\"tags\":" + tags + ",";
  event += "\"content\":\"" + content + "\",";
  event += "\"sig\":\"" + signature + "\"}";
  
  return event;
}

void derivePubkey() {
  hexToBytes(nostrPrivateKeyHex, privKeyBytes, 32);
  uint8_t pubFull[64];
  uECC_Curve curve = uECC_secp256k1();
  uECC_compute_public_key(privKeyBytes, pubFull, curve);
  memcpy(pubKeyBytes, pubFull, 32);
  nostrPubkey = bytesToHex(pubKeyBytes, 32);
  Serial.print("Pubkey: ");
  Serial.println(nostrPubkey);
}

void derivePlantPotPubkey() {
  hexToBytes(plantPotPrivKeyHex, plantPotPrivKeyBytes, 32);
  uint8_t pubFull[64];
  uECC_Curve curve = uECC_secp256k1();
  uECC_compute_public_key(plantPotPrivKeyBytes, pubFull, curve);
  uint8_t pubKeyBytes[32];
  memcpy(pubKeyBytes, pubFull, 32);
  plantPotPubkey = bytesToHex(pubKeyBytes, 32);
  Serial.print("Plant pot pubkey: ");
  Serial.println(plantPotPubkey);
}

String bytesToHex(uint8_t* bytes, int len) {
  String hex = "";
  for (int i = 0; i < len; i++) {
    if (bytes[i] < 16) hex += "0";
    hex += String(bytes[i], HEX);
  }
  return hex;
}

void hexToBytes(const char* hex, uint8_t* bytes, int len) {
  for (int i = 0; i < len; i++) {
    char buf[3] = {hex[i*2], hex[i*2+1], 0};
    bytes[i] = strtol(buf, NULL, 16);
  }
}

void sha256Raw(const uint8_t* data, size_t len, uint8_t* out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

void taggedHash(const uint8_t* tag, const uint8_t* data, size_t len, uint8_t* out) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, tag, 32);
  mbedtls_sha256_update(&ctx, tag, 32);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
}

bool schnorrSign(const uint8_t* privkey, const uint8_t* msg32, uint8_t* sig64) {
  uECC_Curve curve = uECC_secp256k1();
  uint8_t pubFull[64];
  if (!uECC_compute_public_key(privkey, pubFull, curve)) return false;
  uint8_t px[32];
  memcpy(px, pubFull, 32);
  
  uint8_t d[32];
  memcpy(d, privkey, 32);
  if (pubFull[63] & 1) {
    bn_sub(SECP256K1_ORDER, d, d);
  }
  
  uint8_t aux[32];
  for (int i = 0; i < 32; i++) aux[i] = random(256);
  uint8_t t[32], auxHash[32];
  taggedHash(TAG_AUX, aux, 32, auxHash);
  for (int i = 0; i < 32; i++) t[i] = d[i] ^ auxHash[i];
  
  uint8_t nonceData[96];
  memcpy(nonceData, t, 32);
  memcpy(nonceData + 32, px, 32);
  memcpy(nonceData + 64, msg32, 32);
  uint8_t kPrime[32];
  taggedHash(TAG_NONCE, nonceData, 96, kPrime);
  
  bn_mod(kPrime, SECP256K1_ORDER);
  bool isZero = true;
  for (int i = 0; i < 32; i++) if (kPrime[i]) isZero = false;
  if (isZero) return false;
  
  uint8_t R[64];
  if (!uECC_compute_public_key(kPrime, R, curve)) return false;
  uint8_t rx[32];
  memcpy(rx, R, 32);
  
  uint8_t k[32];
  memcpy(k, kPrime, 32);
  if (R[63] & 1) {
    bn_sub(SECP256K1_ORDER, k, k);
  }
  
  uint8_t challengeData[96];
  memcpy(challengeData, rx, 32);
  memcpy(challengeData + 32, px, 32);
  memcpy(challengeData + 64, msg32, 32);
  uint8_t e[32];
  taggedHash(TAG_CHALLENGE, challengeData, 96, e);
  bn_mod(e, SECP256K1_ORDER);
  
  uint8_t ed[32];
  bn_mul_mod(e, d, SECP256K1_ORDER, ed);
  uint8_t s[32];
  bn_add_mod(k, ed, SECP256K1_ORDER, s);
  
  memcpy(sig64, rx, 32);
  memcpy(sig64 + 32, s, 32);
  return true;
}

