#include <SPI.h>
#include <Ethernet.h>

// Network Configuration
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 1, 177);
EthernetServer server(80);

// Monitoring Variables
unsigned long requestCount = 0;
unsigned long lastTime = 0;
const unsigned long interval = 1000; // 1 second interval for request counting
const int baseThreshold = 100; // Base threshold
float adaptiveThreshold = baseThreshold; // Adaptive threshold

// Rolling Average for Adaptive Threshold
const int sampleSize = 10;
unsigned long requestSamples[sampleSize] = {0};
int sampleIndex = 0;

// Alert Settings
const int alertPin = 7; // LED or Buzzer connected to pin 7

// Block List
const int maxBlockListSize = 10;
IPAddress blockList[maxBlockListSize];
int blockListSize = 0;

// Logging Settings
const unsigned long logInterval = 60000; // 1-minute logging interval
unsigned long lastLogTime = 0;

void setup() {
  pinMode(alertPin, OUTPUT);
  Ethernet.begin(mac, ip);
  server.begin();
  Serial.begin(9600);
}

void loop() {
  EthernetClient client = server.available();

  if (client) {
    IPAddress clientIP = client.remoteIP();

    // Check if the client is in the block list
    if (isBlocked(clientIP)) {
      Serial.print("Blocked IP: ");
      Serial.println(clientIP);
      client.stop();
      return;
    }

    // Process incoming request
    processClient(client, clientIP);
  }

  unsigned long currentTime = millis();

  // Update every second
  if (currentTime - lastTime >= interval) {
    lastTime = currentTime;
    updateThresholdAndCheckDDoS();
  }

  // Periodic logging
  if (currentTime - lastLogTime >= logInterval) {
    logStatus();
    lastLogTime = currentTime;
  }
}

// Process the incoming client request
void processClient(EthernetClient& client, IPAddress& clientIP) {
  requestCount++;

  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      // Optionally, log or process the data
    }
  }

  client.stop();
}

// Update the rolling average, adjust threshold, and check for DDoS
void updateThresholdAndCheckDDoS() {
  requestSamples[sampleIndex] = requestCount;
  sampleIndex = (sampleIndex + 1) % sampleSize;

  unsigned long totalRequests = 0;
  for (int i = 0; i < sampleSize; i++) {
    totalRequests += requestSamples[i];
  }
  unsigned long averageRequests = totalRequests / sampleSize;

  adaptiveThreshold = baseThreshold + (averageRequests * 0.5);

  // Check if request count exceeds the adaptive threshold
  if (requestCount > adaptiveThreshold) {
    triggerAlert();
  } else {
    clearAlert();
  }

  // Reset the request count for the next interval
  requestCount = 0;
}

// Trigger alert and block offending IP
void triggerAlert() {
  digitalWrite(alertPin, HIGH); // Trigger alert
  Serial.println("Potential DDoS attack detected!");

  // Block the last IP if not already blocked
  if (blockListSize < maxBlockListSize) {
    IPAddress offendingIP = Ethernet.localIP(); // Get last offending IP
    if (!isBlocked(offendingIP)) {
      blockList[blockListSize] = offendingIP;
      blockListSize++;
      Serial.print("Blocking IP: ");
      Serial.println(offendingIP);
    }
  }
}

// Clear alert state
void clearAlert() {
  digitalWrite(alertPin, LOW);
}

// Check if an IP is in the block list
bool isBlocked(IPAddress ip) {
  for (int i = 0; i < blockListSize; i++) {
    if (blockList[i] == ip) {
      return true;
    }
  }
  return false;
}

// Log current status to Serial
void logStatus() {
  Serial.print("Requests: ");
  Serial.print(requestCount);
  Serial.print(" / Adaptive Threshold: ");
  Serial.println(adaptiveThreshold);
  Serial.print("Blocked IPs: ");
  for (int i = 0; i < blockListSize; i++) {
    Serial.print(blockList[i]);
    if (i < blockListSize - 1) Serial.print(", ");
  }
  Serial.println();
}
