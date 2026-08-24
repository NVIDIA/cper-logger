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

#ifdef CPER_PERSISTENT_STORAGE_ENABLED
#include "cper_manager.hpp"
#endif

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <span>
#include <vector>

#ifdef CPER_PERSISTENT_STORAGE_ENABLED
#ifndef CPER_STORAGE_PATH
#define CPER_STORAGE_PATH "/var/lib/cper-logger"
#endif
#ifndef CPER_MAX_ENTRIES
#define CPER_MAX_ENTRIES 100
#endif
#ifndef CPER_MAX_SIZE_KB
#define CPER_MAX_SIZE_KB 100
#endif
#endif

std::shared_ptr<sdbusplus::asio::connection> conn = nullptr;
#ifdef CPER_PERSISTENT_STORAGE_ENABLED
std::shared_ptr<phosphor::cper::Manager> gManager = nullptr;
#endif

// CPER.Logging.CreateLog "ay"
void cperCreateLog(const std::vector<unsigned char>& cper)
{
    properties prop;
    CPER cp(std::span<const unsigned char>(cper.data(), cper.size()));

    cp.prepareToLog(prop);
    if (prop.empty())
    {
        lg2::error("Error creating log");
        return;
    }

#ifdef CPER_PERSISTENT_STORAGE_ENABLED
    // One persistent D-Bus entry per CPER record (all sections).
    if (gManager != nullptr)
    {
        gManager->store(
            std::vector<uint8_t>(cper.begin(), cper.end()),
            prop[0], cp.getJson());
    }
#endif

    for (const auto& section : prop)
    {
        // Handle multiple cper sections
        cp.log(section, *conn.get());
    }
}

int main(void)
{
    boost::asio::io_context io;
    conn = std::make_shared<sdbusplus::asio::connection>(io);

    conn->request_name("xyz.openbmc_project.CPERLogger");

    auto server = sdbusplus::asio::object_server(conn);

#ifdef CPER_PERSISTENT_STORAGE_ENABLED
    gManager = std::make_shared<phosphor::cper::Manager>(
        server, CPER_STORAGE_PATH, CPER_MAX_ENTRIES,
        static_cast<size_t>(CPER_MAX_SIZE_KB) * 1024ULL);
#endif

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        server.add_interface("/xyz/openbmc_project/cperlogger",
                             "xyz.openbmc_project.CPER");

    iface->register_method("CreateLog", cperCreateLog);

    iface->initialize();
    io.run();
}
