#include <iostream>
#include <cerrno>
#include <cstdint>
#include <string>

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>

// Shared context
extern std::shared_ptr<sdbusplus::asio::connection> conn;

// Method
static const char* svcLogging = "xyz.openbmc_project.Logging";
static const char* objLogging = "/xyz/openbmc_project/logging";
static const char* ifaceLogging = "xyz.openbmc_project.Logging.Create";
static const char* logMethod = "Create";

// Parameters ssa{ss}
static const char* defaultMessage = "CPER logged";
static const char* defaultLevel = "xyz.openbmc_project.Logging.Entry.Level.Warning";
static const std::map<std::string, std::string> additionalData = {
    {"REDFISH_MESSAGE_ID", "NVIDIA.1.0.FatalPlatformError"},
    {"xyz.openbmc_project.Logging.Entry.Resolution", "None"},
    {"namespace", "CPER"}
};

void logCPER(const std::string& keyVal)
{
    std::cout << "Received " << keyVal << std::endl;

    conn->async_method_call(
        // callback
        [](boost::system::error_code ec, sdbusplus::message::message& msg) {
            std::cerr << "Response" << std::endl;
            std::cerr << ec << std::endl;
            if(!ec)
            {
                std::cout << "Success " << std::endl;
            }
            else
            {
                std::cerr << "Error " << msg.get_errno() << std::endl;
            }
        },
        // dbus method
        svcLogging, objLogging, ifaceLogging, logMethod,
        // parameters ssa{ss}
        defaultMessage, defaultLevel, additionalData
    );

    return;
}
