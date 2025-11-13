#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 65432
#define LOG_FILE "logs/client_chat_log.txt"
#define SHIFT 3
#define BUFFER_SIZE 1024

// ---------- Caesar Cipher ----------
void caesar_encrypt(char *text, int shift) {
    for (int i = 0; text[i]; i++) {
        char c = text[i];
        if (c >= 'A' && c <= 'Z') text[i] = ((c - 'A' + shift) % 26) + 'A';
        else if (c >= 'a' && c <= 'z') text[i] = ((c - 'a' + shift) % 26) + 'a';
    }
}

void caesar_decrypt(char *text, int shift) {
    caesar_encrypt(text, 26 - (shift % 26));
}

void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "[%Y-%m-%d %H:%M:%S]", t);
}

void send_message(SOCKET sock, char *message, FILE *logFile) {
    char buffer[BUFFER_SIZE], timestamp[64];
    strcpy(buffer, message);
    caesar_encrypt(buffer, SHIFT);

    get_timestamp(timestamp, sizeof(timestamp));
    if (logFile) {
        fprintf(logFile, "%s Sent (decrypted): %s", timestamp, message);
        fprintf(logFile, "%s Sent (encrypted): %s\n", timestamp, buffer);
        fflush(logFile);
    }

    printf("%s Sent (decrypted): %s", timestamp, message);
    printf("%s Sent (encrypted): %s\n", timestamp, buffer);

    send(sock, buffer, strlen(buffer), 0);
}

int receive_message(SOCKET sock, char *buffer, FILE *logFile) {
    int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) return bytes_received;

    buffer[bytes_received] = '\0';
    char encrypted_copy[BUFFER_SIZE];
    strcpy(encrypted_copy, buffer);

    // Check for server shutdown message
    if (strcmp(buffer, "Server is closed.") == 0) {
        printf("[+] Server closed.\n");
        if (logFile) {
            fprintf(logFile, "[Server closed]: %s\n", buffer);
            fflush(logFile);
        }
        return -1;
    }

    caesar_decrypt(buffer, SHIFT);

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    if (logFile) {
        fprintf(logFile, "%s Received (plain): %s\n", timestamp, buffer);
        fprintf(logFile, "%s Received (encrypted): %s\n", timestamp, encrypted_copy);
        fflush(logFile);
    }

    printf("%s Received (decrypted): %s\n", timestamp, buffer);
    printf("%s Received (encrypted): %s\n", timestamp, encrypted_copy);

    return bytes_received;
}

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    FILE *logFile;

    system("mkdir logs");

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        printf("Invalid IP address\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[+] Connected to server at %s:%d\n", SERVER_IP, PORT);

    logFile = fopen(LOG_FILE, "a");
    if (!logFile) perror("Could not open log file");

    // Receive welcome message
    memset(buffer, 0, sizeof(buffer));
    receive_message(sock, buffer, logFile);

    while (1) {
        printf("You: ");
        fgets(buffer, sizeof(buffer), stdin);

        send_message(sock, buffer, logFile);

        memset(buffer, 0, sizeof(buffer));
        int bytes_received = receive_message(sock, buffer, logFile);
        if (bytes_received <= 0 || bytes_received == -1) {
            printf("[-] Server disconnected. Exiting client.\n");
            break;
        }
    }

    if (logFile) fclose(logFile);
    closesocket(sock);
    WSACleanup();
    return 0;
}
