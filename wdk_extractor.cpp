#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <set>
#include <db_cxx.h>

// Convert a binary buffer to hex string
std::string toHex(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

// Extract all 5-byte sequences from data and return them as hex strings
std::set<std::string> extractWDKs(const uint8_t* data, size_t length) {
    std::set<std::string> wdkSet;
    if (length < 5) return wdkSet;

    for (size_t i = 0; i <= length - 5; ++i) {
        std::string hexSeq = toHex(data + i, 5);
        wdkSet.insert(hexSeq);
    }
    return wdkSet;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <wallet.dat>" << std::endl;
        return 1;
    }

    const char* walletPath = argv[1];
    Db db(nullptr, 0);

    try {
        db.open(nullptr, walletPath, nullptr, DB_BTREE, DB_RDONLY, 0);
        Dbc* cursor;
        db.cursor(nullptr, &cursor, 0);

        Dbt key, data;
        std::set<std::string> foundWDKs;

        while (cursor->get(&key, &data, DB_NEXT) == 0) {
            auto* dataPtr = static_cast<uint8_t*>(data.get_data());
            size_t dataSize = data.get_size();

            auto wdkCandidates = extractWDKs(dataPtr, dataSize);
            foundWDKs.insert(wdkCandidates.begin(), wdkCandidates.end());
        }

        cursor->close();
        db.close(0);

        if (foundWDKs.empty()) {
            std::cout << "No WDK (5-byte) sequences found.\n";
        } else {
            std::cout << "Potential WDK sequences (5-byte hex):\n";
            for (const auto& hex : foundWDKs) {
                std::cout << hex << std::endl;
            }
        }

    } catch (DbException& e) {
        std::cerr << "Error opening wallet: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
