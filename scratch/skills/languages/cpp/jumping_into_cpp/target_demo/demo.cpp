#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <ctime>
#include "getopt.h"
#include "glog/logging.h"
#include <map>

using namespace std;
using namespace std::chrono;


// [2022-04-28 19:39:24,347] INFO 70.20
enum LogLevel { DEBUG, INFO, WARNING, ERROR };

static std::map< LogLevel, const char * > LogLevelStrings = {
   {DEBUG, "DEBUG"},
   {INFO, "INFO"},
   {WARNING, "WARNING"},
   {ERROR, "ERROR"}
};

static std::map< LogLevel, const char * > LogLevelColors = {
   {DEBUG, "\033[1;34m"},
   {INFO, "\033[1;32m"},
   {WARNING, "\033[1;33m"},
   {ERROR, "\033[1;31m"}
};

void log(LogLevel level, string message) {
    time_t t = system_clock::to_time_t(system_clock::now());
    tm * my_tm = localtime(&t);

    cout << "["
         << setfill('0')
         << setw(4) << 1900 + my_tm->tm_year << "-"
         << setw(2) << 1 + my_tm->tm_mon << "-"
         << setw(2) << my_tm->tm_mday << " "
         << setw(2) << my_tm->tm_hour << ":"
         << setw(2) << my_tm->tm_min << ":"
         << setw(2) << my_tm->tm_sec
         << "] " << LogLevelColors[level] 
         << LogLevelStrings[level] << " "
         << message 
         << "\033[0m" << endl;
}



// https://stackoverflow.com/questions/52467531/using-getopt-in-c-to-handle-arguments

// Primary entry point for the demo application
int main(int argc, char* argv[]) {
    log(INFO, "** My Sample Application Starting **");
    system_clock::time_point start = system_clock::now();

    // option longopts[] = {
    //     {"number", optional_argument, NULL, 'n'},
    //     {"show-ends", optional_argument, NULL, 'E'},
    //     {0}
    // };

    // do the thing
    log(DEBUG, "do the thing");
    log(INFO, "do the thing");
    log(WARNING, "do the thing");
    log(ERROR, "do the thing");


    system_clock::time_point end = system_clock::now();   
    duration<double> elapsed_seconds = end-start;
    log(INFO, "Program Finished"); 

    // update the user
    ostringstream ss;
    ss << "Elapsed Time: " << elapsed_seconds.count() << " seconds";
    log(INFO, ss.str());

    // indicate success
    return 0;
}