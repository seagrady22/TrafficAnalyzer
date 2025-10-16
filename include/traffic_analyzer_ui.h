#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sqlite3.h>
#include <ctime>

struct TrafficStats {
    struct TimeStats {
        int total_packets;
        int total_bytes;
        std::map<std::string, int> protocol_counts;
        std::map<std::string, int> top_source_ips;
        std::map<std::string, int> top_dest_ips;
    };

    TimeStats last_hour;
    TimeStats last_day;
    TimeStats last_week;
    TimeStats all_time;
};

struct GeoStats {
    struct CountryStats {
        int packet_count;
        int byte_count;
        std::vector<std::string> top_cities;
        std::vector<std::string> top_organizations;
    };

    std::map<std::string, CountryStats> countries;
    std::vector<std::pair<double, double>> traffic_flow;  // Source and destination coordinates
};

class TrafficAnalyzerUI {
public:
    TrafficAnalyzerUI(const std::string& db_path);
    ~TrafficAnalyzerUI();

    // Data analysis methods
    TrafficStats getTrafficStats();
    GeoStats getGeoStats();
    std::vector<std::pair<time_t, int>> getTrafficOverTime(const std::string& time_range = "1h");
    std::vector<std::pair<std::string, int>> getTopProtocols(const std::string& time_range = "1h");
    std::vector<std::pair<std::string, int>> getTopIPs(const std::string& time_range = "1h", bool source = true);
    std::vector<std::pair<std::string, int>> getTopCountries(const std::string& time_range = "1h");
    std::vector<std::pair<std::string, int>> getTopOrganizations(const std::string& time_range = "1h");

    // Visualization methods
    void generateTrafficReport(const std::string& output_path);
    void generateGeoMap(const std::string& output_path);
    void generateProtocolDistribution(const std::string& output_path);
    void generateTimeSeriesPlot(const std::string& output_path);

    // Utility methods
    std::string formatBytes(size_t bytes);
    std::string formatTimeRange(const std::string& time_range);

private:
    sqlite3* db_;
    std::string db_path_;

    // Helper methods
    std::string getTimeRangeSQL(const std::string& time_range);
    void executeQuery(const std::string& query, 
                     std::function<void(sqlite3_stmt*)> row_callback);
}; 