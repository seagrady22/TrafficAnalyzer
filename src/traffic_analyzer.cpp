#include "traffic_analyzer.h"
#include <iostream>
#include <cstring>
#include <ctime>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <iomanip>
#include <curl/curl.h>
#include <json/json.h>
#include <vector>
#include <thread>
#include <csignal>
#include <atomic>
#include <mutex>
#include <condition_variable>

// Add these constants at the top of the file after the includes
const int MAX_REQUESTS_PER_MINUTE = 45;  // ip-api.com's free tier limit
const int RATE_LIMIT_WINDOW_MS = 60000;  // 1 minute in milliseconds
static std::vector<time_t> request_timestamps;  // Track request timestamps for rate limiting
static std::atomic<bool> should_exit(false);  // Global flag for graceful shutdown
static std::mutex shutdown_mutex;
static std::condition_variable shutdown_cv;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Initiating graceful shutdown..." << std::endl;
    should_exit = true;
    shutdown_cv.notify_all();
}

TrafficAnalyzer::TrafficAnalyzer(const std::string& interface, const std::string& db_path)
    : interface_(interface), db_path_(db_path), pcap_handle_(nullptr), db_(nullptr), is_capturing_(false) {
    
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGQUIT, signalHandler);
}

TrafficAnalyzer::~TrafficAnalyzer() {
    stopCapture();
    if (db_) {
        sqlite3_close(db_);
    }
}

bool TrafficAnalyzer::startCapture() {
    if (is_capturing_) {
        return true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // First try to get the device info
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return false;
    }

    bool found_interface = false;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        if (d->name == interface_) {
            found_interface = true;
            break;
        }
    }
    pcap_freealldevs(alldevs);

    if (!found_interface) {
        std::cerr << "Interface " << interface_ << " not found" << std::endl;
        return false;
    }

    // Open the device
    pcap_handle_ = pcap_open_live(interface_.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!pcap_handle_) {
        std::cerr << "Error opening interface " << interface_ << ": " << errbuf << std::endl;
        return false;
    }

    // Try to set monitor mode
    if (pcap_can_set_rfmon(pcap_handle_) == 1) {
        if (pcap_set_rfmon(pcap_handle_, 1) != 0) {
            std::cerr << "Warning: Could not set monitor mode" << std::endl;
        }
    }

    if (!initializeDatabase()) {
        std::cerr << "Failed to initialize database" << std::endl;
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    std::cout << "Successfully opened interface and initialized database" << std::endl;
    is_capturing_ = true;

    // Start the capture loop in non-blocking mode
    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
        std::cerr << "Warning: Could not set non-blocking mode: " << errbuf << std::endl;
    }

    // Main capture loop with graceful shutdown support
    while (!should_exit) {
        int result = pcap_dispatch(pcap_handle_, 1, packetHandler, reinterpret_cast<u_char*>(this));
        if (result == -1) {
            std::cerr << "Error in packet capture: " << pcap_geterr(pcap_handle_) << std::endl;
            break;
        }
        
        // Small sleep to prevent CPU spinning
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    stopCapture();
    return true;
}

void TrafficAnalyzer::stopCapture() {
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    is_capturing_ = false;
}

bool TrafficAnalyzer::isCapturing() const {
    return is_capturing_;
}

// Callback function for CURL
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool TrafficAnalyzer::getLocationInfo(const std::string& ip, std::string& country, std::string& region, 
                                    std::string& city, double& lat, double& lon) {
    // First check if we have cached data
    const char* selectSQL = "SELECT country, region, city, latitude, longitude, last_updated "
                           "FROM locations WHERE ip = ? AND last_updated > datetime('now', '-1 day');";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, selectSQL, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            country = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            region = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            city = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            lat = sqlite3_column_double(stmt, 3);
            lon = sqlite3_column_double(stmt, 4);
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
    }

    // Implement rate limiting
    time_t now = time(nullptr);
    request_timestamps.push_back(now);
    
    // Remove timestamps older than the rate limit window
    while (!request_timestamps.empty() && 
           (now - request_timestamps.front()) * 1000 > RATE_LIMIT_WINDOW_MS) {
        request_timestamps.erase(request_timestamps.begin());
    }
    
    // Check if we've exceeded the rate limit
    if (request_timestamps.size() >= MAX_REQUESTS_PER_MINUTE) {
        std::cerr << "Rate limit exceeded. Waiting for next window..." << std::endl;
        // Sleep for the remaining time in the window
        int sleep_time = RATE_LIMIT_WINDOW_MS - (now - request_timestamps.front()) * 1000;
        if (sleep_time > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));
        }
        request_timestamps.clear();
    }

    // If no cached data, query ip-api.com
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL" << std::endl;
        return false;
    }

    // Check if the IP is IPv6
    bool isIPv6 = ip.find(':') != std::string::npos;
    std::string url = "http://ip-api.com/json/" + ip + (isIPv6 ? "?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query" : "?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query");
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // 10 second timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);  // 5 second connect timeout

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "CURL failed: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        std::cerr << "HTTP request failed with code: " << http_code << std::endl;
        return false;
    }

    // Parse JSON response
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse JSON response" << std::endl;
        return false;
    }

    if (root["status"].asString() != "success") {
        std::cerr << "IP lookup failed: " << root["message"].asString() << std::endl;
        return false;
    }

    country = root["country"].asString();
    region = root["regionName"].asString();
    city = root["city"].asString();
    lat = root["lat"].asDouble();
    lon = root["lon"].asDouble();

    // Get additional information
    std::string isp = root["isp"].asString();
    std::string org = root["org"].asString();
    std::string as = root["as"].asString();

    // Cache the results with additional fields
    const char* insertSQL = "INSERT OR REPLACE INTO locations (ip, country, region, city, latitude, longitude, isp, organization, as_number, last_updated) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));";
    
    if (sqlite3_prepare_v2(db_, insertSQL, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, country.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, region.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, city.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_double(stmt, 5, lat);
        sqlite3_bind_double(stmt, 6, lon);
        sqlite3_bind_text(stmt, 7, isp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, org.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, as.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error caching location data: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    return true;
}

void TrafficAnalyzer::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    TrafficAnalyzer* analyzer = reinterpret_cast<TrafficAnalyzer*>(userData);
    
    // Get the Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    std::cout << "\n=== Packet Captured ===\n";
    std::cout << "Length: " << pkthdr->len << " bytes\n";
    
    // Print MAC addresses
    std::cout << "MAC Source: ";
    for(int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(eth_header->ether_shost[i]);
        if(i < 5) std::cout << ":";
    }
    std::cout << std::dec << "\n";

    std::cout << "MAC Dest: ";
    for(int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(eth_header->ether_dhost[i]);
        if(i < 5) std::cout << ":";
    }
    std::cout << std::dec << "\n";

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        
        std::cout << "IP Source: " << source_ip << "\n";
        std::cout << "IP Dest: " << dest_ip << "\n";
        
        // Get location information
        std::string source_country, source_region, source_city;
        std::string dest_country, dest_region, dest_city;
        double source_lat, source_lon, dest_lat, dest_lon;
        
        if (analyzer->getLocationInfo(source_ip, source_country, source_region, source_city, source_lat, source_lon)) {
            std::cout << "Source Location: " << source_city << ", " << source_region << ", " << source_country << "\n";
            // Query additional information from the database
            const char* selectSQL = "SELECT isp, organization, as_number FROM locations WHERE ip = ?;";
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(analyzer->db_, selectSQL, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, source_ip, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::cout << "Source ISP: " << sqlite3_column_text(stmt, 0) << "\n";
                    std::cout << "Source Organization: " << sqlite3_column_text(stmt, 1) << "\n";
                    std::cout << "Source AS Number: " << sqlite3_column_text(stmt, 2) << "\n";
                }
                sqlite3_finalize(stmt);
            }
        }
        
        if (analyzer->getLocationInfo(dest_ip, dest_country, dest_region, dest_city, dest_lat, dest_lon)) {
            std::cout << "Destination Location: " << dest_city << ", " << dest_region << ", " << dest_country << "\n";
            // Query additional information from the database
            const char* selectSQL = "SELECT isp, organization, as_number FROM locations WHERE ip = ?;";
            sqlite3_stmt* stmt;
            if (sqlite3_prepare_v2(analyzer->db_, selectSQL, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, dest_ip, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    std::cout << "Destination ISP: " << sqlite3_column_text(stmt, 0) << "\n";
                    std::cout << "Destination Organization: " << sqlite3_column_text(stmt, 1) << "\n";
                    std::cout << "Destination AS Number: " << sqlite3_column_text(stmt, 2) << "\n";
                }
                sqlite3_finalize(stmt);
            }
        }
        
        std::cout << "Protocol: ";
        
        // Handle different protocols
        uint8_t protocol = ip_header->ip_p;
        if (protocol == IPPROTO_TCP) {
            std::cout << "TCP\n";
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << "\n";
            std::cout << "Dest Port: " << ntohs(tcp_header->th_dport) << "\n";
        }
        else if (protocol == IPPROTO_UDP) {
            std::cout << "UDP\n";
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            std::cout << "Source Port: " << ntohs(udp_header->uh_sport) << "\n";
            std::cout << "Dest Port: " << ntohs(udp_header->uh_dport) << "\n";
        }
        else if (protocol == IPPROTO_ICMP) {
            std::cout << "ICMP\n";
        }
        else {
            std::cout << "Other (" << static_cast<int>(protocol) << ")\n";
        }
    }
    
    std::cout << "==================\n" << std::flush;
    
    analyzer->storePacket(pkthdr, packet);
}

bool TrafficAnalyzer::initializeDatabase() {
    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Enable foreign keys and WAL mode for better performance and reliability
    const char* pragmaSQL = 
        "PRAGMA foreign_keys = ON;"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;";
    
    if (sqlite3_exec(db_, pragmaSQL, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error setting database pragmas: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Drop existing tables
    const char* dropTablesSQL =
        "DROP TABLE IF EXISTS packets;"
        "DROP TABLE IF EXISTS locations;";

    char* errMsg = nullptr;
    if (sqlite3_exec(db_, dropTablesSQL, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error dropping tables: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    const char* createTablesSQL = 
        "CREATE TABLE packets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "length INTEGER,"
        "source_ip TEXT,"
        "destination_ip TEXT,"
        "protocol TEXT,"
        "source_port INTEGER,"
        "destination_port INTEGER,"
        "ttl INTEGER"
        ");"
        
        "CREATE TABLE locations ("
        "ip TEXT PRIMARY KEY,"
        "country TEXT,"
        "region TEXT,"
        "city TEXT,"
        "latitude REAL,"
        "longitude REAL,"
        "isp TEXT,"
        "organization TEXT,"
        "as_number TEXT,"
        "last_updated DATETIME"
        ");"
        
        "CREATE INDEX idx_packets_timestamp ON packets(timestamp);"
        "CREATE INDEX idx_packets_protocol ON packets(protocol);"
        "CREATE INDEX idx_packets_source_ip ON packets(source_ip);"
        "CREATE INDEX idx_packets_destination_ip ON packets(destination_ip);";

    if (sqlite3_exec(db_, createTablesSQL, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating tables: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

bool TrafficAnalyzer::storePacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Parse packet headers
    struct ether_header* eth_header = (struct ether_header*)packet;
    
    // Only store IP packets
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return true;  // Not an error, just not storing non-IP packets
    }
    
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    
    // Get protocol information
    std::string protocol;
    int source_port = 0;
    int dest_port = 0;
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            protocol = "TCP";
            struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = ntohs(tcp_header->th_sport);
            dest_port = ntohs(tcp_header->th_dport);
            break;
        }
        case IPPROTO_UDP: {
            protocol = "UDP";
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = ntohs(udp_header->uh_sport);
            dest_port = ntohs(udp_header->uh_dport);
            break;
        }
        case IPPROTO_ICMP:
            protocol = "ICMP";
            break;
        default:
            protocol = "Other";
    }
    
    // Get current timestamp
    time_t now = time(nullptr);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Prepare SQL statement with all fields
    const char* insertSQL = 
        "INSERT INTO packets (timestamp, length, source_ip, destination_ip, protocol, "
        "source_port, destination_port, ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, insertSQL, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Error preparing statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    // Bind all parameters
    sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, pkthdr->len);
    sqlite3_bind_text(stmt, 3, source_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, dest_ip, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, protocol.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, source_port);
    sqlite3_bind_int(stmt, 7, dest_port);
    sqlite3_bind_int(stmt, 8, ip_header->ip_ttl);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error executing statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

void TrafficAnalyzer::cleanupOldData(int days_to_keep) {
    if (!db_) {
        std::cerr << "Database not initialized" << std::endl;
        return;
    }

    // Delete old packets
    const char* deletePacketsSQL = 
        "DELETE FROM packets WHERE timestamp < datetime('now', ?);";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, deletePacketsSQL, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string days_str = "-" + std::to_string(days_to_keep) + " days";
        sqlite3_bind_text(stmt, 1, days_str.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error deleting old packets: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    // Delete old location data that's not referenced by any packets
    const char* deleteLocationsSQL = 
        "DELETE FROM locations WHERE last_updated < datetime('now', ?) "
        "AND ip NOT IN (SELECT source_ip FROM packets) "
        "AND ip NOT IN (SELECT destination_ip FROM packets);";
    
    if (sqlite3_prepare_v2(db_, deleteLocationsSQL, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string days_str = "-" + std::to_string(days_to_keep) + " days";
        sqlite3_bind_text(stmt, 1, days_str.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Error deleting old locations: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    // Vacuum the database to reclaim space
    if (sqlite3_exec(db_, "VACUUM;", nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error vacuuming database: " << sqlite3_errmsg(db_) << std::endl;
    }
}

void TrafficAnalyzer::optimizeDatabase() {
    if (!db_) {
        std::cerr << "Database not initialized" << std::endl;
        return;
    }

    // Rebuild indexes
    const char* rebuildIndexesSQL = 
        "REINDEX idx_packets_timestamp;"
        "REINDEX idx_packets_source_ip;"
        "REINDEX idx_packets_destination_ip;"
        "REINDEX idx_packets_protocol;";
    
    if (sqlite3_exec(db_, rebuildIndexesSQL, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error rebuilding indexes: " << sqlite3_errmsg(db_) << std::endl;
    }

    // Update statistics
    if (sqlite3_exec(db_, "ANALYZE;", nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::cerr << "Error analyzing database: " << sqlite3_errmsg(db_) << std::endl;
    }
} 