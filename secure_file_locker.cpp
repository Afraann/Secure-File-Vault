#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

using namespace std;

// Generate 128-bit AES key from password using SHA-256
void generateKey(const string &password, unsigned char key[16]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)password.c_str(), password.size(), hash);
    memcpy(key, hash, 16); // first 16 bytes for AES-128
}

// Encrypt or decrypt a file
bool processFile(const string &inFile, const string &outFile,
                 const unsigned char key[16], bool encrypt) {
                 const unsigned char iv[16] = "123456789012345"; // 15 chars + '\0' = 16

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    } else {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    }

    ifstream in(inFile, ios::binary);
    ofstream out(outFile, ios::binary);
    if (!in || !out) {
        cerr << "File error!\n";
        return false;
    }

    vector<unsigned char> buffer(1024);
    vector<unsigned char> outBuffer(1040);
    int outLen;

    while (in.good()) {
        in.read((char*)buffer.data(), buffer.size());
        int bytesRead = in.gcount();

        if (encrypt) {
            EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), bytesRead);
        } else {
            EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), bytesRead);
        }
        out.write((char*)outBuffer.data(), outLen);
    }

    if (encrypt) {
        EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen);
    } else {
        EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen);
    }
    out.write((char*)outBuffer.data(), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {
    cout << "Secure File Locker (C++ + AES)\n";
    cout << "Enter password: ";
    string password;
    getline(cin, password);

    unsigned char key[16];
    generateKey(password, key);

    cout << "Choose: 1) Encrypt  2) Decrypt: ";
    int choice;
    cin >> choice;
    cin.ignore();

    cout << "Enter input file path: ";
    string inFile;
    getline(cin, inFile);

    cout << "Enter output file path: ";
    string outFile;
    getline(cin, outFile);

    bool success = false;
    if (choice == 1) {
        success = processFile(inFile, outFile, key, true);
    } else if (choice == 2) {
        success = processFile(inFile, outFile, key, false);
    }

    if (success) {
        cout << "Operation successful!\n";
    } else {
        cout << "Operation failed.\n";
    }

    return 0;
}
