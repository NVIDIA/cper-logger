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

#pragma once

#include <nlohmann/json.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <map>
#include <memory>
#include <string>

static constexpr const char* cperEntryIface = "xyz.openbmc_project.CPER.Entry";
static constexpr const char* cperEntryBasePath =
    "/xyz/openbmc_project/cper/entry/";

// D-Bus object at /xyz/openbmc_project/cper/entry/<id> implementing
// xyz.openbmc_project.CPER.Entry.
//
//   - DiagnosticDataType  : "CPER" or "CPERSection"
//   - DiagnosticInfo      : full libcper JSON (all decoded fields)
//   - CperLogFilePath     : path to raw CPER binary on the BMC filesystem
class CperEntry
{
  public:
    CperEntry(sdbusplus::asio::object_server& server, uint64_t id,
              const std::map<std::string, std::string>& commonProps,
              const nlohmann::json& fullJson, const std::string& filePath);

    ~CperEntry()
    {
        server.remove_interface(iface);
    }

    const std::string& getDiagnosticDataType() const
    {
        return diagnosticDataType;
    }
    const std::string& getDiagnosticInfo() const
    {
        return diagnosticInfo;
    }
    const std::string& getCperLogFilePath() const
    {
        return cperLogFilePath;
    }

  private:
    sdbusplus::asio::object_server& server;
    std::shared_ptr<sdbusplus::asio::dbus_interface> iface;

    std::string diagnosticDataType;
    std::string diagnosticInfo;
    std::string cperLogFilePath;
};
