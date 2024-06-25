#ifndef LoggerH
#define LoggerH

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <ctime>
#include <iomanip>

enum LogLevel
{
    DEBUG,
    WARNING,
    INFO,
    ERR,
};

void initLogger(const std::string& filename);
std::string getCurrentDateTime();
std::string logLevelToString(LogLevel level);
void printLog(LogLevel level, const std::string& message);

#endif