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

#include "cper_entry.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>

static std::string toTypeString(const std::string& diagnosticDataType)
{
    if (diagnosticDataType == "CPERSection")
    {
        return "xyz.openbmc_project.CPER.Entry.DiagnosticDataType.CPERSection";
    }
    if (diagnosticDataType == "CPER")
    {
        return "xyz.openbmc_project.CPER.Entry.DiagnosticDataType.CPER";
    }
    lg2::error("Unknown DiagnosticDataType value: {1}", "1", diagnosticDataType);
    return "xyz.openbmc_project.CPER.Entry.DiagnosticDataType.CPER";
}

CperEntry::CperEntry(sdbusplus::asio::object_server& server, uint64_t id,
                     const std::map<std::string, std::string>& commonProps,
                     const nlohmann::json& fullJson,
                     const std::string& filePath) :
    server(server)
{
    auto get = [&](const std::string& key) -> std::string {
        auto it = commonProps.find(key);
        return it != commonProps.end() ? it->second : "";
    };

    diagnosticDataType = toTypeString(get("diagnosticDataType"));

    diagnosticInfo = fullJson.is_null()
                         ? ""
                         : fullJson.dump(-1, ' ', false,
                                         nlohmann::json::error_handler_t::replace);

    cperLogFilePath = filePath;

    std::string path =
        std::string(cperEntryBasePath) + std::format("{:010}", id);

    iface = server.add_interface(path, cperEntryIface);

    iface->register_property("DiagnosticDataType", diagnosticDataType);
    iface->register_property("DiagnosticInfo", diagnosticInfo);
    iface->register_property("CperLogFilePath", cperLogFilePath);

    iface->initialize();

    lg2::debug("CPER entry created at {1}", "1", path);
}
