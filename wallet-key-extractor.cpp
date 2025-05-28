#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include "wallet_parser.h"
#include "wdk_scanner.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <wallet.dat path>" << std::endl;
        return EXIT_FAILURE;
    }

    const std::string wallet_path = argv[1];

    if (!std::filesystem::exists(wallet_path)) {
        std::cerr << "Error: File not found -> " << wallet_path << std::endl;
        return EXIT_FAILURE;
    }

    try {
        std::vector<uint8_t> wallet_data = WalletParser::read_wallet(wallet_path);
        std::string extracted_wdk = WDKScanner::extract_wdk(wallet_data);

        if (!extracted_wdk.empty()) {
            std::cout << "WDK Found: " << extracted_wdk << std::endl;
        } else {
            std::cout << "WDK not found in wallet." << std::endl;
        }

    } catch (const std::exception& ex) {
        std::cerr << "Exception occurred: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
