## Adaptive Request Monitoring System with DDoS Protection

## Overview

This project implements an Adaptive Request Monitoring System using an Arduino with Ethernet capabilities. The system monitors incoming requests and adapts dynamically to detect and respond to potential Distributed Denial-of-Service (DDoS) attacks. When suspicious activity is detected, such as an unusual spike in request rates, the system triggers an alert and can block the offending IP address.
## Feature 

1. Real-time Request Monitoring:

- Tracks the number of incoming requests in real-time.
- Utilizes a rolling average to adjust the detection threshold dynamically.

2. Adaptive Threshold Calculation:

- The system adapts its threshold based on recent activity, making it more sensitive to potential attacks while reducing false positives.

3. Alert System:

- An LED or buzzer connected to pin 7 serves as an alert mechanism when a potential DDoS attack is detected.
4. IP Blocking Mechanism:

- Blocks IP addresses that exceed the adaptive threshold.
- Maintains a block list of up to 10 IP addresses.
## Components 

- Arduino Board with Ethernet Shield
- Ethernet Cable connected to a network with IP address 192.168.1.177
- LED/Buzzer connected to digital pin 7 for alert notifications
## How It Work 

1. Setup:

- The system initializes by setting up the Ethernet connection, server, and alert pin.
- A rolling average array for request samples is initialized.

2. Monitoring Loop:

- The loop continuously checks for client connections.
- If a client connects, the system verifies whether the client's IP is on the block list. If it is, the connection is terminated immediately.
- The number of incoming requests is counted, and data is processed, even if not logged.

3. Adaptive Threshold Adjustment:

- Every second, the system updates the rolling average of requests.
- The adaptive threshold is recalculated as the base threshold plus half of the rolling average.

4. Attack Detection:

- If the request count within the interval exceeds the adaptive threshold, the alert pin is triggered, and the offending IP is blocked.
- The system logs relevant data, including the number of requests and the current threshold, for further analysis.

5. IP Blocking:

- Offending IPs are added to a block list, preventing them from making further requests.
## Configuration 

## Network Configuration
- MAC Address: 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
- IP Address: 192, 168, 1, 177
- Server Port: 80
## Adaptive Threshold and Rolling Average
- Base Threshold: 100 requests per second.
- Rolling Average Sample Size: 10 intervals.
- Adaptive Threshold Formula: baseThreshold + (averageRequests * 0.5)
## Alert and Blocking Settings
- Alert Pin: 7 (Can be connected to an LED or buzzer).
- Maximum Block List Size: 10 IP addresses.
## Usage 
- Connect the Arduino to your network using an Ethernet shield.
- Upload the code to the Arduino using the Arduino IDE.
- Monitor the Serial Output to observe request counts and alerts.
- Adjust the Base Threshold as needed depending on expected network traffic.


## Pro & Cons

### Pros

1. **DDoS Detection and Mitigation**:  
   The program includes functionality to detect potential DDoS attacks by monitoring the rate of incoming requests and comparing them against an adaptive threshold. This helps to protect the server from being overwhelmed by malicious traffic.

2. **Adaptive Threshold Mechanism**:  
   Instead of using a static threshold, the program dynamically adjusts the request threshold based on the rolling average of requests. This makes it more resilient to varying levels of legitimate traffic and reduces the chances of false positives.

3. **Logging and Monitoring**:  
   The program periodically logs request counts, adaptive thresholds, and blocked IP addresses, providing valuable information for monitoring server activity and troubleshooting.

4. **Blocking Capability**:  
   It can block IP addresses that are suspected of malicious behavior, helping to prevent further unwanted traffic from those sources. This is done dynamically, based on detected anomalies.

5. **Simple and Easy to Integrate**:  
   The program uses standard Arduino libraries and is straightforward to integrate into existing Ethernet-based projects. The code is modular, making it easy to understand and modify.

6. **Alert System**:  
   The inclusion of an alert mechanism (using an LED or buzzer) provides a quick, visual or audible indication of potential issues, allowing for rapid response to threats.

### Cons

1. **Limited Block List Size**:  
   The block list is capped at a maximum size of 10 IP addresses, which might not be sufficient for handling large-scale DDoS attacks with numerous offending IPs.

2. **Simple Detection Logic**:  
   The detection method is based on request rate, which might not catch more sophisticated DDoS attacks that use low-rate or distributed techniques to evade detection.

3. **Resource Constraints**:  
   Since the program is designed to run on Arduino hardware, it is limited by the processing power and memory of the microcontroller. This can limit the scalability and effectiveness of the DDoS mitigation.

4. **No Persistent Storage**:  
   The block list and request logs are stored in memory and will be lost if the device is restarted. There is no mechanism to persist this information to non-volatile storage.

5. **False Positives**:  
   In high-traffic environments, legitimate spikes in traffic could be mistaken for DDoS attacks, leading to unnecessary blocking of IPs and potential denial of service to legitimate users.

6. **Manual Reset Required**:  
   If an IP is blocked due to a false positive, it requires manual intervention to reset or clear the block list, which can be inconvenient and may disrupt legitimate service.


## Future Enhancement

- Logging: Implement detailed logging for each request for further analysis.
- Web Interface: Create a simple web interface to monitor and manage the system remotely.
- Advanced Blocking: Use more sophisticated techniques for identifying malicious IPs.
## License

[MIT](https://choosealicense.com/licenses/mit/)

