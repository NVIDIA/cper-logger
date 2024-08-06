/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cper.hpp"

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

std::shared_ptr<sdbusplus::asio::connection> conn = nullptr;

// CPER.Logging.CreateLog "s"
void cperCreateLog(const std::string& cperPath)
{
    CPER cp(cperPath);

    cp.log(conn);
}

int main(void)
{
    boost::asio::io_context io;
    conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->request_name("xyz.openbmc_project.CPERLogger");

    auto server = sdbusplus::asio::object_server(conn);

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server.add_interface("/xyz/openbmc_project/cperlogger",
                             "xyz.openbmc_project.CPER");

    iface->register_method("CreateLog", cperCreateLog);

    iface->initialize();
    io.run();
}
