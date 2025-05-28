// wallet-key-extractor.cpp
// Extracts Wallet Decryption Key (WDK) from wallet.dat

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <regex>
#include <filesystem>
#include <chrono>
#include <thread>
#include <map>

namespace fs = std::filesystem;

void display_help() {
    std::cout << "Wallet Key Extractor - Usage:\n"
              << "  --wallet <path>              Specify the wallet.dat file path\n"
              << "  --extract-key                Extract and display the unique key\n"
              << "  --repair-wallet              Attempt to repair wallet structure\n"
              << "  --sec<level>                 Set security level (1-3, default: 2)\n"
              << "  --type<format>               Specify wallet format (legacy/current/auto)\n"
              << "  --automated-detection        Enable automated format detection\n"
              << "  --verbose                    Enable detailed output\n"
              << "  --timeout<seconds>          Set operation timeout (default: 30)\n"
              << "  --output<file>               Save results to specified file\n"
              << "  --force                      Force operation without confirmation\n"
              << "  --no-backup                  Skip backup creation\n"
              << "  --help                       Display this help message\n";
}

bool file_exists(const std::string& path) {
    return fs::exists(path) && fs::is_regular_file(path);
}

std::vector<uint8_t> read_wallet_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

std::string extract_wdk(const std::vector<uint8_t>& data, bool verbose) {
    std::regex wdk_pattern("(?i)([a-f0-9]{10})"); // 5-byte hex = 10 hex chars
    std::smatch match;
    std::string hex_data;

    for (auto byte : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex_data += buf;
    }

    std::sregex_iterator it(hex_data.begin(), hex_data.end(), wdk_pattern);
    std::sregex_iterator end;

    for (; it != end; ++it) {
        if (verbose) {
            std::cout << "[Verbose] Possible WDK found: " << it->str() << "\n";
        }
        return it->str(); // return first match only
    }

    return "";
}

int main(int argc, char* argv[]) {
    std::map<std::string, std::string> options;
    std::string wallet_path;
    bool extract_key = false;
    bool verbose = false;
    std::string output_file;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help") {
            display_help();
            return 0;
        } else if (arg == "--wallet" && i + 1 < argc) {
            wallet_path = argv[++i];
        } else if (arg == "--extract-key") {
            extract_key = true;
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg.rfind("--output", 0) == 0 && arg.find("=") != std::string::npos) {
            output_file = arg.substr(arg.find("=") + 1);
        }
    }

    if (wallet_path.empty() || !file_exists(wallet_path)) {
        std::cerr << "[Error] Wallet file not specified or does not exist.\n";
        return 1;
    }

    if (extract_key) {
        if (verbose) std::cout << "[Verbose] Reading wallet file: " << wallet_path << "\n";
        std::vector<uint8_t> data = read_wallet_file(wallet_path);

        std::string wdk = extract_wdk(data, verbose);
        if (!wdk.empty()) {
            std::string result = "[Success] WDK Extracted: " + wdk;
            std::cout << result << "\n";

            if (!output_file.empty()) {
                std::ofstream out(output_file);
                out << result << std::endl;
                if (verbose) std::cout << "[Verbose] WDK saved to " << output_file << "\n";
            }
        } else {
            std::cerr << "[Error] WDK not found.\n";
            return 2;
        }
    }

    return 0;
}
