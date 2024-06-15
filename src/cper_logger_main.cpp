#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include "cper.hpp"

std::shared_ptr<sdbusplus::asio::connection> conn = nullptr;

// CPER.Logging.CreateLog "s"
void CPER_Logging_CreateLog(const std::string& cper_path)
{
    CPER cp(cper_path);

    cp.log();
}

int main(int, char**)
{
    boost::asio::io_context io;
    conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->request_name("xyz.openbmc_project.CPERLogger");

    auto server = sdbusplus::asio::object_server(conn);

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server.add_interface("/xyz/openbmc_project/cperlogger",
                             "xyz.openbmc_project.CPER.Logging");

    iface->register_method("CreateLog", CPER_Logging_CreateLog);

    iface->initialize();
    io.run();
}
