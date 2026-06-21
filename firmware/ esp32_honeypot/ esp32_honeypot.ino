/*
 * ESP32 Low-Interaction IoT Honeypot - starter firmware
 * Final-year project: ESP32 IoT honeypot with an agentic AI threat-analysis pipeline
 *
 * What this does:
 *   - Connects to your WiFi
 *   - Opens a fake "Telnet" service on port 23 (a classic IoT attack target)
 *   - For every connection, logs the source IP, a timestamp, and any bytes
 *     the client sends (e.g. login attempts)
 *   - Prints each event to the Serial Monitor as one line of JSON
 *   - POSTs each event as JSON to the FastAPI backend (set BACKEND_URL below)
 *
 * This is a DEFENSIVE tool: it only records what connects to it. It never
 * attacks anything. For now, run it on an isolated/guest network - NOT your
 * main home network, and do NOT expose it to the internet yet. We'll handle
 * safe internet exposure later, during the data-collection phase.
 */

#include <WiFi.h>
#include <HTTPClient.h>   // lets the ESP32 act as an HTTP client and POST to our backend

// ---- 1. Fill these in ----
const char* WIFI_SSID = "YOUR_WIFI_NAME";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// The FastAPI backend's /events endpoint. Replace 192.168.1.100 with the LAN IP
// of the computer running the backend. Find it with:
//   macOS:  ipconfig getifaddr en0
//   Linux:  hostname -I
// The ESP32 and that computer MUST be on the same WiFi network. Use http://
// (not https), and the port uvicorn prints (default 8000).
const char* BACKEND_URL = "http://192.168.1.100:8000/events";

// ---- 2. Honeypot settings ----
const uint16_t HONEYPOT_PORT = 23;      // fake Telnet
WiFiServer honeypot(HONEYPOT_PORT);
const char* FAKE_BANNER = "\r\nLogin: ";  // makes it look like a real login prompt

void connectWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Honeypot IP address: ");
  Serial.println(WiFi.localIP());   // <-- you'll connect to THIS address to test
}

// Send one JSON event to the FastAPI backend over HTTP POST.
// This is the bridge from the honeypot device to the analysis backend.
void postEvent(const String& json) {
  // HTTP needs a working network connection. If WiFi dropped, skip (don't crash).
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("!! WiFi not connected, skipping POST");
    return;
  }

  HTTPClient http;
  http.begin(BACKEND_URL);                              // where to send the event
  http.addHeader("Content-Type", "application/json");   // tell the server it's JSON
  http.setConnectTimeout(3000);                         // give up after 3s if backend is down,
  http.setTimeout(3000);                                // so a dead backend can't freeze the honeypot

  int code = http.POST(json);                           // do the POST; returns the HTTP status code
  if (code > 0) {
    // A positive number is the server's reply. 200 = accepted and stored.
    Serial.printf("POST -> HTTP %d\n", code);
  } else {
    // A negative number is a client-side failure (e.g. couldn't connect).
    Serial.printf("POST failed: %s\n", http.errorToString(code).c_str());
  }
  http.end();   // close the connection and free its resources
}

// Build one JSON event, print it to Serial (for debugging), and POST it to the backend.
// JSON makes it trivial for the backend to parse.
void logEvent(const String& clientIP, const String& data) {
  String safe = data;
  safe.replace("\\", "\\\\");
  safe.replace("\"", "\\\"");
  safe.replace("\r", "\\r");
  safe.replace("\n", "\\n");

  String line = "{";
  line += "\"timestamp_ms\":" + String(millis()) + ",";   // swap for real NTP time next phase
  line += "\"src_ip\":\"" + clientIP + "\",";
  line += "\"port\":" + String(HONEYPOT_PORT) + ",";
  line += "\"data\":\"" + safe + "\"";
  line += "}";

  Serial.println(line);   // keep printing to Serial — handy for debugging and demos
  postEvent(line);        // NEW: also send the event to the backend
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  connectWiFi();
  honeypot.begin();
  Serial.print("Honeypot listening on port ");
  Serial.println(HONEYPOT_PORT);
}

void loop() {
  WiFiClient client = honeypot.available();
  if (client) {
    String clientIP = client.remoteIP().toString();
    Serial.println("-- connection from " + clientIP);
    client.print(FAKE_BANNER);

    // Read whatever the client sends, for up to 5 seconds of inactivity
    String captured = "";
    unsigned long lastActivity = millis();
    while (client.connected() && (millis() - lastActivity < 5000)) {
      while (client.available()) {
        captured += (char)client.read();
        lastActivity = millis();   // reset the timer whenever data arrives
      }
      delay(10);
    }

    logEvent(clientIP, captured);
    client.stop();
  }
}
