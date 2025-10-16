#include "traffic_analyzer_ui.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <ctime>
#include <cstring>

TrafficAnalyzerUI::TrafficAnalyzerUI(const std::string& db_path) : db_path_(db_path), db_(nullptr) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db_) << std::endl;
    }
}

TrafficAnalyzerUI::~TrafficAnalyzerUI() {
    if (db_) {
        sqlite3_close(db_);
    }
}

std::string TrafficAnalyzerUI::getTimeRangeSQL(const std::string& time_range) {
    if (time_range == "1h") {
        return "datetime('now', '-1 hour')";
    } else if (time_range == "1d") {
        return "datetime('now', '-1 day')";
    } else if (time_range == "1w") {
        return "datetime('now', '-7 days')";
    } else if (time_range == "all") {
        return "datetime('1970-01-01')";
    }
    return "datetime('now', '-1 hour')";  // Default to 1 hour
}

void TrafficAnalyzerUI::executeQuery(const std::string& query, 
                                   std::function<void(sqlite3_stmt*)> row_callback) {
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            row_callback(stmt);
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Error executing query: " << sqlite3_errmsg(db_) << std::endl;
    }
}

std::string TrafficAnalyzerUI::formatBytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = bytes;
    
    while (size >= 1024 && unit < 4) {
        size /= 1024;
        unit++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return ss.str();
}

std::string TrafficAnalyzerUI::formatTimeRange(const std::string& time_range) {
    if (time_range == "1h") return "Last Hour";
    if (time_range == "1d") return "Last Day";
    if (time_range == "1w") return "Last Week";
    if (time_range == "all") return "All Time";
    return "Last Hour";
}

TrafficStats TrafficAnalyzerUI::getTrafficStats() {
    TrafficStats stats = {};  // Initialize all fields to 0/empty
    
    if (!db_) {
        std::cerr << "Database connection not initialized" << std::endl;
        return stats;
    }
    
    // Helper function to populate TimeStats
    auto populateTimeStats = [this](TrafficStats::TimeStats& ts, const std::string& time_range) {
        ts = {};  // Initialize all fields to 0/empty
        std::string time_condition = getTimeRangeSQL(time_range);
        
        // Get total packets and bytes
        std::string query = "SELECT COUNT(*), COALESCE(SUM(length), 0) FROM packets WHERE timestamp > " + time_condition;
        executeQuery(query, [&ts](sqlite3_stmt* stmt) {
            ts.total_packets = sqlite3_column_int(stmt, 0);
            ts.total_bytes = sqlite3_column_int(stmt, 1);
        });
        
        // Get protocol counts
        query = "SELECT protocol, COUNT(*) FROM packets WHERE timestamp > " + time_condition + 
                " GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 10";
        executeQuery(query, [&ts](sqlite3_stmt* stmt) {
            const char* protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (protocol) {
                int count = sqlite3_column_int(stmt, 1);
                ts.protocol_counts[protocol] = count;
            }
        });
        
        // Get top source IPs
        query = "SELECT source_ip, COUNT(*) FROM packets WHERE timestamp > " + time_condition + 
                " GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10";
        executeQuery(query, [&ts](sqlite3_stmt* stmt) {
            const char* ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (ip) {
                int count = sqlite3_column_int(stmt, 1);
                ts.top_source_ips[ip] = count;
            }
        });
        
        // Get top destination IPs
        query = "SELECT destination_ip, COUNT(*) FROM packets WHERE timestamp > " + time_condition + 
                " GROUP BY destination_ip ORDER BY COUNT(*) DESC LIMIT 10";
        executeQuery(query, [&ts](sqlite3_stmt* stmt) {
            const char* ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (ip) {
                int count = sqlite3_column_int(stmt, 1);
                ts.top_dest_ips[ip] = count;
            }
        });
    };
    
    populateTimeStats(stats.last_hour, "1h");
    populateTimeStats(stats.last_day, "1d");
    populateTimeStats(stats.last_week, "1w");
    populateTimeStats(stats.all_time, "all");
    
    return stats;
}

GeoStats TrafficAnalyzerUI::getGeoStats() {
    GeoStats stats = {};  // Initialize all fields to 0/empty
    
    if (!db_) {
        std::cerr << "Database connection not initialized" << std::endl;
        return stats;
    }
    
    // Get country statistics
    std::string query = 
        "SELECT l.country, COUNT(*), COALESCE(SUM(p.length), 0), GROUP_CONCAT(DISTINCT l.city), "
        "GROUP_CONCAT(DISTINCT l.organization) "
        "FROM packets p "
        "LEFT JOIN locations l ON p.source_ip = l.ip "
        "WHERE p.timestamp > datetime('now', '-1 day') AND l.country IS NOT NULL "
        "GROUP BY l.country";
    
    executeQuery(query, [&stats](sqlite3_stmt* stmt) {
        const char* country = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (!country) return;
        
        GeoStats::CountryStats& cs = stats.countries[country];
        cs.packet_count = sqlite3_column_int(stmt, 1);
        cs.byte_count = sqlite3_column_int(stmt, 2);
        
        // Parse cities
        const char* cities = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (cities) {
            std::stringstream ss(cities);
            std::string city;
            while (std::getline(ss, city, ',')) {
                if (!city.empty()) {
                    cs.top_cities.push_back(city);
                }
            }
        }
        
        // Parse organizations
        const char* orgs = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        if (orgs) {
            std::stringstream ss(orgs);
            std::string org;
            while (std::getline(ss, org, ',')) {
                if (!org.empty()) {
                    cs.top_organizations.push_back(org);
                }
            }
        }
    });
    
    // Get traffic flow coordinates
    query = 
        "SELECT s.latitude, s.longitude, d.latitude, d.longitude "
        "FROM packets p "
        "LEFT JOIN locations s ON p.source_ip = s.ip "
        "LEFT JOIN locations d ON p.destination_ip = d.ip "
        "WHERE p.timestamp > datetime('now', '-1 hour') "
        "AND s.latitude IS NOT NULL AND s.longitude IS NOT NULL "
        "AND d.latitude IS NOT NULL AND d.longitude IS NOT NULL "
        "LIMIT 1000";
    
    executeQuery(query, [&stats](sqlite3_stmt* stmt) {
        double src_lat = sqlite3_column_double(stmt, 0);
        double src_lon = sqlite3_column_double(stmt, 1);
        double dst_lat = sqlite3_column_double(stmt, 2);
        double dst_lon = sqlite3_column_double(stmt, 3);
        stats.traffic_flow.push_back(std::make_pair(src_lat, src_lon));
        stats.traffic_flow.push_back(std::make_pair(dst_lat, dst_lon));
    });
    
    return stats;
}

void TrafficAnalyzerUI::generateTrafficReport(const std::string& output_path) {
    std::ofstream report(output_path);
    if (!report.is_open()) {
        std::cerr << "Error opening report file: " << output_path << std::endl;
        return;
    }
    
    TrafficStats stats = getTrafficStats();
    GeoStats geo_stats = getGeoStats();
    
    // Generate HTML report with enhanced styling
    report << "<!DOCTYPE html>\n<html>\n<head>\n"
           << "<title>Network Traffic Analysis Report</title>\n"
           << "<style>\n"
           << "body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n"
           << "h1, h2 { color: #333; }\n"
           << ".container { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }\n"
           << "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background-color: white; }\n"
           << "th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }\n"
           << "th { background-color: #f8f9fa; color: #333; }\n"
           << "tr:nth-child(even) { background-color: #f9f9f9; }\n"
           << ".geo-details { display: flex; flex-wrap: wrap; gap: 20px; }\n"
           << ".geo-card { flex: 1; min-width: 300px; background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n"
           << "</style>\n</head>\n<body>\n";
    
    // Summary section
    report << "<div class='container'>\n"
           << "<h1>Network Traffic Analysis Report</h1>\n"
           << "<h2>Traffic Summary</h2>\n"
           << "<table>\n"
           << "<tr><th>Time Range</th><th>Total Packets</th><th>Total Bytes</th></tr>\n"
           << "<tr><td>Last Hour</td><td>" << stats.last_hour.total_packets 
           << "</td><td>" << formatBytes(stats.last_hour.total_bytes) << "</td></tr>\n"
           << "<tr><td>Last Day</td><td>" << stats.last_day.total_packets 
           << "</td><td>" << formatBytes(stats.last_day.total_bytes) << "</td></tr>\n"
           << "<tr><td>Last Week</td><td>" << stats.last_week.total_packets 
           << "</td><td>" << formatBytes(stats.last_week.total_bytes) << "</td></tr>\n"
           << "<tr><td>All Time</td><td>" << stats.all_time.total_packets 
           << "</td><td>" << formatBytes(stats.all_time.total_bytes) << "</td></tr>\n"
           << "</table>\n</div>\n";
    
    // Protocol distribution
    report << "<div class='container'>\n"
           << "<h2>Protocol Distribution (Last Hour)</h2>\n"
           << "<table>\n"
           << "<tr><th>Protocol</th><th>Count</th><th>Percentage</th></tr>\n";
    
    int total_protocols = 0;
    for (const auto& p : stats.last_hour.protocol_counts) {
        total_protocols += p.second;
    }
    
    for (const auto& p : stats.last_hour.protocol_counts) {
        double percentage = (static_cast<double>(p.second) / total_protocols) * 100;
        report << "<tr><td>" << p.first << "</td><td>" << p.second 
               << "</td><td>" << std::fixed << std::setprecision(2) << percentage << "%</td></tr>\n";
    }
    report << "</table>\n</div>\n";
    
    // Geographical Analysis
    report << "<div class='container'>\n"
           << "<h2>Geographical Analysis</h2>\n"
           << "<div class='geo-details'>\n";
    
    // Country Statistics
    report << "<div class='geo-card'>\n"
           << "<h3>Traffic by Country</h3>\n"
           << "<table>\n"
           << "<tr><th>Country</th><th>Packets</th><th>Bytes</th><th>Cities</th><th>Organizations</th></tr>\n";
    
    for (const auto& c : geo_stats.countries) {
        report << "<tr><td>" << c.first << "</td>"
               << "<td>" << c.second.packet_count << "</td>"
               << "<td>" << formatBytes(c.second.byte_count) << "</td>"
               << "<td>";
        
        // Add cities
        for (size_t i = 0; i < std::min(c.second.top_cities.size(), size_t(3)); ++i) {
            if (i > 0) report << ", ";
            report << c.second.top_cities[i];
        }
        report << "</td><td>";
        
        // Add organizations
        for (size_t i = 0; i < std::min(c.second.top_organizations.size(), size_t(3)); ++i) {
            if (i > 0) report << ", ";
            report << c.second.top_organizations[i];
        }
        report << "</td></tr>\n";
    }
    report << "</table>\n</div>\n";
    
    // Traffic Flow Statistics
    if (!geo_stats.traffic_flow.empty()) {
        report << "<div class='geo-card'>\n"
               << "<h3>Recent Traffic Flows</h3>\n"
               << "<table>\n"
               << "<tr><th>Source Location</th><th>Destination Location</th></tr>\n";
        
        for (size_t i = 0; i < geo_stats.traffic_flow.size(); i += 2) {
            if (i + 1 < geo_stats.traffic_flow.size()) {
                report << "<tr><td>(" << std::fixed << std::setprecision(6) 
                       << geo_stats.traffic_flow[i].first << ", " 
                       << geo_stats.traffic_flow[i].second << ")</td><td>("
                       << geo_stats.traffic_flow[i+1].first << ", "
                       << geo_stats.traffic_flow[i+1].second << ")</td></tr>\n";
            }
        }
        report << "</table>\n</div>\n";
    }
    
    report << "</div>\n</div>\n";
    report << "</body>\n</html>";
    report.close();
}

// ... Implement other visualization methods as needed ... 