#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <cper_logger.hpp>

std::shared_ptr<sdbusplus::asio::connection> conn = nullptr;

int main(int, char**)
{
    boost::asio::io_context io;
    conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->request_name("xyz.openbmc_project.CPERLogger");

    auto server = sdbusplus::asio::object_server(conn);

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server.add_interface("/xyz/openbmc_project/cperlogger",
                             "xyz.openbmc_project.CPER");

    iface->register_method("CreateLog", logCPER);

    iface->initialize();
    io.run();
}
