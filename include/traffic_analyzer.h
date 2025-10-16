#pragma once

#include <string>
#include <memory>
#include <pcap.h>
#include <sqlite3.h>

class TrafficAnalyzer {
public:
    TrafficAnalyzer(const std::string& interface, const std::string& db_path);
    ~TrafficAnalyzer();

    bool startCapture();
    void stopCapture();
    bool isCapturing() const;
    void cleanupOldData(int days_to_keep);
    void optimizeDatabase();

private:
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    bool initializeDatabase();
    bool storePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    bool getLocationInfo(const std::string& ip, std::string& country, std::string& region, 
                        std::string& city, double& lat, double& lon);

    std::string interface_;
    std::string db_path_;
    pcap_t* pcap_handle_;
    sqlite3* db_;
    bool is_capturing_;
}; 