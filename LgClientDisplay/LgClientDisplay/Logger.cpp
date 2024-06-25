#include "Logger.h"

std::ofstream logFile;

void initLogger(const std::string& filename) {
	logFile.open(filename, std::ios::app);
	if (!logFile.is_open()) {
		std::cerr << "Failed to open log file" << std::endl;
	}
}

void printLog(LogLevel level, const std::string& message) {
	if (logFile.is_open()) {
		std::string logMessage = getCurrentDateTime() + logLevelToString(level) + message;
		logFile << logMessage << std::endl;
		std::cout << logMessage << std::endl;
	}
}

std::string getCurrentDateTime() {
	std::time_t now = std::time(nullptr);
	std::tm tm;
	localtime_s(&tm, &now);
	std::ostringstream oss;
	oss << (tm.tm_year + 1900) << '-'
		<< std::setw(2) << std::setfill('0') << (tm.tm_mon + 1) << '-'
		<< std::setw(2) << std::setfill('0') << tm.tm_mday << ' '
		<< std::setw(2) << std::setfill('0') << tm.tm_hour << ':'
		<< std::setw(2) << std::setfill('0') << tm.tm_min << ':'
		<< std::setw(2) << std::setfill('0') << tm.tm_sec;
	return oss.str();
}

std::string logLevelToString(LogLevel level) {
	switch (level) {
	case LogLevel::DEBUG: return "[DEBUG]";
	case LogLevel::INFO: return "[INFO]";
	case LogLevel::WARNING: return "[WARNING]";
	case LogLevel::ERR: return "[ERROR]";
	default: throw std::invalid_argument("Unknown log level");
	}
}


