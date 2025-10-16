#include "../include/traffic_analyzer.h"
#include <iostream>
#include <string>
#include <csignal>
#include <thread>
#include <chrono>

namespace {
    volatile std::sig_atomic_t running = 1;

    void signalHandler(int signal) {
        running = 0;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <database_path>" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    std::string db_path = argv[2];

    // Set up signal handler for graceful shutdown
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try {
        TrafficAnalyzer analyzer(interface, db_path);
        
        std::cout << "Starting packet capture on interface: " << interface << std::endl;
        if (!analyzer.startCapture()) {
            std::cerr << "Failed to start packet capture" << std::endl;
            return 1;
        }

        std::cout << "Packet capture started. Press Ctrl+C to stop." << std::endl;
        
        // Keep the main thread alive while capturing
        while (running && analyzer.isCapturing()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        analyzer.stopCapture();
        std::cout << "Packet capture stopped." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 