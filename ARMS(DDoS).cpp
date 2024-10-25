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
const int baseThreshold = 100; // Base threshold for DDoS detection
float adaptiveThreshold = baseThreshold; // Adaptive threshold

// Rolling Average & Adaptive Threshold
const int sampleSize = 10;
unsigned long requestSamples[sampleSize] = {0};
int sampleIndex = 0;
float smoothingFactor = 0.1; // Adjust for exponential smoothing

// Alert & Block List Settings
const int alertPin = 7; // LED or Buzzer connected to pin 7
const int maxBlockListSize = 10;
IPAddress blockList[maxBlockListSize];
int blockListSize = 0;
unsigned long blockDurations[maxBlockListSize];
const unsigned long blockTime = 300000; // 5 minutes block duration

// Logging Settings
const unsigned long logInterval = 60000; // 1-minute logging interval
unsigned long lastLogTime = 0;

void setup() {
  pinMode(alertPin, OUTPUT);
  Ethernet.begin(mac, ip);
  server.begin();
  Serial.begin(9600);
  Serial.println("DDoS Monitor Initialized");
}

void loop() {
  EthernetClient client = server.available();

  if (client) {
    IPAddress clientIP = client.remoteIP();

    // Check if the client is in the block list
    if (isBlocked(clientIP)) {
      Serial.print("Blocked IP tried to connect: ");
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

  // Unblock expired IPs
  unblockExpiredIPs(currentTime);
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

  // Apply exponential smoothing for adaptive threshold
  adaptiveThreshold = adaptiveThreshold * (1 - smoothingFactor) + averageRequests * smoothingFactor;

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

  IPAddress offendingIP = Ethernet.localIP(); // Get last offending IP
  if (!isBlocked(offendingIP)) {
    blockIP(offendingIP, millis());
  }
}

// Block IP for a set duration
void blockIP(IPAddress ip, unsigned long currentTime) {
  if (blockListSize < maxBlockListSize) {
    blockList[blockListSize] = ip;
    blockDurations[blockListSize] = currentTime + blockTime;
    blockListSize++;
    Serial.print("Blocking IP: ");
    Serial.println(ip);
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

// Unblock IPs whose block duration has expired
void unblockExpiredIPs(unsigned long currentTime) {
  for (int i = 0; i < blockListSize; i++) {
    if (currentTime >= blockDurations[i]) {
      Serial.print("Unblocking IP: ");
      Serial.println(blockList[i]);

      // Shift the array to remove the unblocked IP
      for (int j = i; j < blockListSize - 1; j++) {
        blockList[j] = blockList[j + 1];
        blockDurations[j] = blockDurations[j + 1];
      }
      blockListSize--;
      i--; // Re-evaluate the current index after shift
    }
  }
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
