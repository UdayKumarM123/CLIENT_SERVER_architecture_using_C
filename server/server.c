#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 65432
#define LOG_FILE "logs/server_chat_log.txt"
#define SHIFT 3  // Caesar cipher shift
#define BUFFER_SIZE 1024

typedef struct {
    SOCKET client_socket;
    struct sockaddr_in client_addr;
    FILE *logFile;
} client_info;

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

// Get timestamp
void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, size, "[%Y-%m-%d %H:%M:%S]", t);
}

// Send message (with encryption and logging)
void send_message(SOCKET sock, char *message, FILE *logFile, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE], timestamp[64];
    strcpy(buffer, message);
    caesar_encrypt(buffer, SHIFT);

    get_timestamp(timestamp, sizeof(timestamp));

    if (logFile) {
        fprintf(logFile, "%s Sent to ('%s', %d) (decrypted): %s", timestamp,
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), message);
        fprintf(logFile, "%s Sent to ('%s', %d) (encrypted): %s\n", timestamp,
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
        fflush(logFile);
    }

    printf("%s Sent (decrypted): %s", timestamp, message);
    printf("%s Sent (encrypted): %s\n", timestamp, buffer);

    send(sock, buffer, strlen(buffer), 0);
}

// Send plain message (without encryption)
void send_plain_message(SOCKET sock, char *message) {
    send(sock, message, strlen(message), 0);
}

// Receive message with decryption and logging
int receive_message(SOCKET sock, char *buffer, FILE *logFile, struct sockaddr_in client_addr) {
    int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) return bytes_received;

    buffer[bytes_received] = '\0';
    char encrypted_copy[BUFFER_SIZE];
    strcpy(encrypted_copy, buffer);

    caesar_decrypt(buffer, SHIFT);

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    if (logFile) {
        fprintf(logFile, "%s From ('%s', %d) (decrypted): %s\n", timestamp,
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
        fprintf(logFile, "%s From ('%s', %d) (encrypted): %s\n", timestamp,
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), encrypted_copy);
        fflush(logFile);
    }

    printf("%s Received (encrypted): %s\n", timestamp, encrypted_copy);
    printf("%s Received (decrypted): %s\n", timestamp, buffer);

    return bytes_received;
}

// Thread function for each client
DWORD WINAPI client_thread(LPVOID param) {
    client_info *info = (client_info *)param;
    SOCKET client_socket = info->client_socket;
    FILE *logFile = info->logFile;
    struct sockaddr_in client_addr = info->client_addr;
    char buffer[BUFFER_SIZE];

    printf("[+] Client connected: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = receive_message(client_socket, buffer, logFile, client_addr);
        if (bytes_received <= 0) {
            printf("[-] Client disconnected: %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        }

        printf("Server: ");
        fgets(buffer, sizeof(buffer), stdin);

        // Exit server if typed 'exit'
        if (strncmp(buffer, "exit", 4) == 0) {
            char close_msg[] = "Server is closed.";
            printf("[+] Shutting down server...\n");
            send_plain_message(client_socket, close_msg); // send plain text
            closesocket(client_socket);
            exit(0);
        }

        send_message(client_socket, buffer, logFile, client_addr);
    }

    closesocket(client_socket);
    free(info);
    return 0;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    FILE *logFile;

    system("mkdir logs");

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 5) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    printf("A subdirectory or file logs already exists.\n");
    printf("[+] Server listening on port %d...\n", PORT);
    printf("[+] Type 'exit' to quit server at any time.\n");

    // --- Welcome message on console only ---
    printf("[Server decrypted]: Welcome to the secure server!\n");
    printf("[Server encrypted]: Zhofrph wr wkh vhfxuh vhuyhu!\n\n");

    logFile = fopen(LOG_FILE, "a");
    if (!logFile) perror("Could not open log file");

    while (1) {
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }

        client_info *info = (client_info *)malloc(sizeof(client_info));
        info->client_socket = client_socket;
        info->client_addr = client_addr;
        info->logFile = logFile;

        // Send welcome message to client (logged and encrypted)
        char welcome_msg[] = "Welcome to the secure server!";
        send_message(client_socket, welcome_msg, logFile, client_addr);

        HANDLE hThread = CreateThread(NULL, 0, client_thread, info, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }

    if (logFile) fclose(logFile);
    closesocket(server_fd);
    WSACleanup();
    return 0;
}
