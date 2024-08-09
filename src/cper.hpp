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

#ifndef CPER_HPP
#define CPER_HPP

#include <nlohmann/json.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <map>
#include <string>

class CPER
{

  public:
    // Constructor from filename
    CPER(const std::string& filename);

    // Log
    void log(sdbusplus::asio::connection&) const;

    // Get
    bool isValid() const
    {
        return jsonValid;
    }
    const std::map<std::string, std::string>& getProperties() const
    {
        return additionalData;
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
    void readPldmFile(const std::string& filename);

    // Populate additionalData from json for logging
    void prepareToLog();

    // helpers

    void convertHeader(const nlohmann::json& header);
    void convertSectionDescriptor(const nlohmann::json& desc);
    void convertSection(const nlohmann::json& section);
    void convertSectionPCIe(const nlohmann::json& section);
    void convertSectionNVIDIA(const nlohmann::json& section);

    size_t findWorst(const nlohmann::json::array_t& descs,
                     const nlohmann::json::array_t& sections,
                     size_t nelems) const;

    std::string toDbusSeverity(const std::string& severity) const;
    std::string toNvSeverity(int severity) const;
    std::string toHexString(int num, size_t width) const;
    std::string toBase64String(const std::vector<uint8_t>& data) const;

    // input file
    std::string cperPath;

    // from input
    std::vector<uint8_t> cperData;

    nlohmann::json jsonData;
    bool jsonValid;

    // saved flags
    std::string cperSeverity;
    std::string sectionType;

    // for output
    std::map<std::string, std::string> additionalData;
};

#endif // CPER_HPP
