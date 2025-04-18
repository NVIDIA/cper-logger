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
#include <sdbusplus/asio/connection.hpp>

#include <map>
#include <span>
#include <string>

using namespace nlohmann::literals;

using properties = std::vector<std::map<std::string, std::string>>;

class CPER
{

  public:
    // Constructor to create json from file
    CPER(const std::span<const unsigned char> data);

    // Populate properties from json for logging
    void prepareToLog(properties& dumpData) const;
    void addDumpDefaults(std::map<std::string, std::string>& log) const;

    // Log
    void log(const std::map<std::string, std::string>&,
             sdbusplus::asio::connection&) const;

    // Get
    bool isValid() const
    {
        return jsonData.is_object();
    }
    const nlohmann::json& getJson() const
    {
        return jsonData;
    }

  private:
#ifdef CPER_LOGGER_DEBUG_TRACE
    // Load from libcper json
    void readJsonFile(const std::string& filename);
#endif

    // Load from pldmd data
    void readPldmData(std::span<const unsigned char> data);

    // helpers
    std::string toDbusSeverity(const std::string& severity) const;
    std::string toBase64String(const std::vector<uint8_t>& data) const;

    // input file (needed to fwd the notification)
    std::string cperPath;

    // raw cper
    std::vector<uint8_t> cperData;

    // cper json
    nlohmann::json jsonData;

}; // class
