#include "traffic_analyzer_ui.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <iomanip>
#include <chrono>
#include <thread>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <vector>
#include <algorithm>

// ANSI color codes for better output
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string BLUE = "\033[34m";
const std::string MAGENTA = "\033[35m";
const std::string CYAN = "\033[36m";
const std::string RESET = "\033[0m";

// Helper function to get terminal width
int getTerminalWidth() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
}

// Helper function to print a horizontal line
void printSeparator() {
    int width = getTerminalWidth();
    std::cout << std::string(width, '-') << std::endl;
}

// Helper function to print centered text
void printCentered(const std::string& text) {
    int width = getTerminalWidth();
    int padding = (width - text.length()) / 2;
    std::cout << std::string(padding, ' ') << text << std::endl;
}

void printUsage() {
    printSeparator();
    printCentered("Network Traffic Analyzer CLI");
    printSeparator();
    std::cout << "\nUsage: traffic_analyzer_cli <command> [options]\n\n"
              << "Commands:\n"
              << "  " << GREEN << "report" << RESET << " <db_path> <output_file>  Generate HTML traffic report\n"
              << "  " << GREEN << "stats" << RESET << " <db_path> [time_range]    Show traffic statistics\n"
              << "  " << GREEN << "geo" << RESET << " <db_path> [time_range]      Show geographical statistics\n"
              << "  " << GREEN << "live" << RESET << " <db_path>                  Monitor traffic in real-time\n"
              << "  " << GREEN << "top" << RESET << " <db_path> [n]              Show top N IPs/Protocols\n"
              << "  " << GREEN << "help" << RESET << "                           Show this help message\n\n"
              << "Time ranges: 1h (hour), 1d (day), 1w (week), all\n";
    printSeparator();
}

void showStats(const std::string& db_path, const std::string& time_range = "1h") {
    TrafficAnalyzerUI analyzer(db_path);
    auto stats = analyzer.getTrafficStats();
    
    printSeparator();
    printCentered("Traffic Statistics - " + analyzer.formatTimeRange(time_range));
    printSeparator();
    
    // Get the appropriate time stats based on the time range
    const auto& time_stats = [&]() -> const TrafficStats::TimeStats& {
        if (time_range == "1h") return stats.last_hour;
        if (time_range == "1d") return stats.last_day;
        if (time_range == "1w") return stats.last_week;
        return stats.all_time;
    }();
    
    // Print summary
    std::cout << "\n" << CYAN << "Summary:" << RESET << "\n"
              << "  Total Packets: " << YELLOW << time_stats.total_packets << RESET << "\n"
              << "  Total Bytes: " << YELLOW << analyzer.formatBytes(time_stats.total_bytes) << RESET << "\n\n";
    
    // Print protocol distribution
    std::cout << CYAN << "Protocol Distribution:" << RESET << "\n";
    int total_protocols = 0;
    for (const auto& p : time_stats.protocol_counts) {
        total_protocols += p.second;
    }
    
    for (const auto& p : time_stats.protocol_counts) {
        double percentage = (static_cast<double>(p.second) / total_protocols) * 100;
        std::cout << "  " << std::left << std::setw(15) << p.first 
                  << std::right << std::setw(8) << p.second << " packets "
                  << "(" << std::fixed << std::setprecision(1) << percentage << "%)" << "\n";
    }
    
    // Print top IPs
    std::cout << "\n" << CYAN << "Top Source IPs:" << RESET << "\n";
    int count = 0;
    for (const auto& ip : time_stats.top_source_ips) {
        if (count++ >= 5) break;
        std::cout << "  " << std::left << std::setw(15) << ip.first 
                  << std::right << std::setw(8) << ip.second << " packets\n";
    }
    
    std::cout << "\n" << CYAN << "Top Destination IPs:" << RESET << "\n";
    count = 0;
    for (const auto& ip : time_stats.top_dest_ips) {
        if (count++ >= 5) break;
        std::cout << "  " << std::left << std::setw(15) << ip.first 
                  << std::right << std::setw(8) << ip.second << " packets\n";
    }
    
    printSeparator();
}

void showGeoStats(const std::string& db_path, const std::string& time_range = "1h") {
    TrafficAnalyzerUI analyzer(db_path);
    auto stats = analyzer.getGeoStats();
    
    printSeparator();
    printCentered("Geographical Statistics - " + analyzer.formatTimeRange(time_range));
    printSeparator();
    
    // Sort countries by packet count
    std::vector<std::pair<std::string, GeoStats::CountryStats>> sorted_countries(
        stats.countries.begin(), stats.countries.end());
    std::sort(sorted_countries.begin(), sorted_countries.end(),
              [](const auto& a, const auto& b) {
                  return a.second.packet_count > b.second.packet_count;
              });
    
    for (const auto& [country, data] : sorted_countries) {
        std::cout << "\n" << CYAN << country << ":" << RESET << "\n"
                  << "  Packets: " << YELLOW << data.packet_count << RESET << "\n"
                  << "  Bytes: " << YELLOW << analyzer.formatBytes(data.byte_count) << RESET << "\n"
                  << "  Top Cities: ";
        
        for (size_t i = 0; i < std::min(data.top_cities.size(), size_t(3)); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << MAGENTA << data.top_cities[i] << RESET;
        }
        
        std::cout << "\n  Top Organizations: ";
        for (size_t i = 0; i < std::min(data.top_organizations.size(), size_t(3)); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << BLUE << data.top_organizations[i] << RESET;
        }
        std::cout << "\n";
    }
    
    printSeparator();
}

void monitorLive(const std::string& db_path) {
    TrafficAnalyzerUI analyzer(db_path);
    std::cout << "Starting live traffic monitoring... (Press 'q' to quit)\n";
    
    // Set terminal to non-canonical mode
    struct termios old_settings, new_settings;
    tcgetattr(STDIN_FILENO, &old_settings);
    new_settings = old_settings;
    new_settings.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    
    while (true) {
        // Check for 'q' key press
        char c;
        if (read(STDIN_FILENO, &c, 1) > 0 && c == 'q') {
            break;
        }
        
        // Clear screen and show updated stats
        std::cout << "\033[2J\033[1;1H";  // Clear screen and move cursor to top
        showStats(db_path, "1h");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
}

void showTop(const std::string& db_path, int n = 10) {
    TrafficAnalyzerUI analyzer(db_path);
    auto stats = analyzer.getTrafficStats();
    
    printSeparator();
    printCentered("Top " + std::to_string(n) + " Statistics");
    printSeparator();
    
    // Show top protocols
    std::cout << "\n" << CYAN << "Top Protocols:" << RESET << "\n";
    std::vector<std::pair<std::string, int>> protocols(
        stats.last_hour.protocol_counts.begin(),
        stats.last_hour.protocol_counts.end());
    std::sort(protocols.begin(), protocols.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (int i = 0; i < std::min(n, static_cast<int>(protocols.size())); ++i) {
        std::cout << "  " << std::left << std::setw(15) << protocols[i].first
                  << std::right << std::setw(8) << protocols[i].second << " packets\n";
    }
    
    // Show top source IPs
    std::cout << "\n" << CYAN << "Top Source IPs:" << RESET << "\n";
    std::vector<std::pair<std::string, int>> source_ips(
        stats.last_hour.top_source_ips.begin(),
        stats.last_hour.top_source_ips.end());
    std::sort(source_ips.begin(), source_ips.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (int i = 0; i < std::min(n, static_cast<int>(source_ips.size())); ++i) {
        std::cout << "  " << std::left << std::setw(15) << source_ips[i].first
                  << std::right << std::setw(8) << source_ips[i].second << " packets\n";
    }
    
    printSeparator();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "help") {
        printUsage();
        return 0;
    }
    
    if (command == "report") {
        if (argc != 4) {
            std::cerr << RED << "Error: report command requires database path and output file\n" << RESET;
            printUsage();
            return 1;
        }
        
        TrafficAnalyzerUI analyzer(argv[2]);
        analyzer.generateTrafficReport(argv[3]);
        std::cout << GREEN << "Report generated successfully: " << argv[3] << RESET << std::endl;
    }
    else if (command == "stats") {
        if (argc < 3) {
            std::cerr << RED << "Error: stats command requires database path\n" << RESET;
            printUsage();
            return 1;
        }
        
        std::string time_range = (argc > 3) ? argv[3] : "1h";
        showStats(argv[2], time_range);
    }
    else if (command == "geo") {
        if (argc < 3) {
            std::cerr << RED << "Error: geo command requires database path\n" << RESET;
            printUsage();
            return 1;
        }
        
        std::string time_range = (argc > 3) ? argv[3] : "1h";
        showGeoStats(argv[2], time_range);
    }
    else if (command == "live") {
        if (argc != 3) {
            std::cerr << RED << "Error: live command requires database path\n" << RESET;
            printUsage();
            return 1;
        }
        
        monitorLive(argv[2]);
    }
    else if (command == "top") {
        if (argc < 3) {
            std::cerr << RED << "Error: top command requires database path\n" << RESET;
            printUsage();
            return 1;
        }
        
        int n = (argc > 3) ? std::atoi(argv[3]) : 10;
        showTop(argv[2], n);
    }
    else {
        std::cerr << RED << "Error: Unknown command '" << command << "'\n" << RESET;
        printUsage();
        return 1;
    }
    
    return 0;
} 