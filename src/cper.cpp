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

#include <libcper/cper-parse-str.h>

#include <boost/asio.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/file_posix.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <utility>

extern "C"
{
#include <libcper/Cper.h>
}

// Public functions
int constructDiagnosticData(nlohmann::json& out, const nlohmann::json& secdIt,
                            const nlohmann::json& secIt)
{
    nlohmann::json::array_t arr;
    arr.push_back(secdIt);
    out["sectionDescriptors"] = std::move(arr);

    nlohmann::json::array_t secarr;
    secarr.push_back(secIt);
    out["sections"] = std::move(secarr);

    return 0;
}

CPER::CPER(std::span<const unsigned char> data)
{
    readPldmData(data);

#ifdef CPER_LOGGER_DEBUG_TRACE
    if (this->jsonData.empty() || this->jsonData.is_discarded())
    {
        // Debug-mode - Try the incoming file as json
        readJsonFile(filename);
    }
#endif
}

void CPER::addDumpDefaults(std::map<std::string, std::string>& log) const
{
    log["diagnosticData"] = toBase64String(this->cperData);
    log["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";

    // override these defaults
    log["diagnosticDataType"] = "CPER";
    log["cperSeverity"] = "Unknown";
}

void readIntKey(const std::string& match, const std::string& key,
                const nlohmann::json& obj, int64_t& valueOut)
{
    if (match != key)
    {
        return;
    }
    const int64_t* name = obj.get_ptr<const int64_t*>();
    if (obj != nullptr)
    {
        valueOut = *name;
    }
}

void readStrKey(const std::string& match, const std::string& key,
                const nlohmann::json& obj, std::string& valueOut)
{
    if (match != key)
    {
        return;
    }
    const std::string* name = obj.get_ptr<const std::string*>();
    if (obj != nullptr)
    {
        valueOut = *name;
    }
}

struct Header
{
    std::string severity;
    int64_t code = std::numeric_limits<int64_t>::max();
    std::string notificationType;
    std::string timestamp;
    std::string time;
};

static Header readHeader(const nlohmann::json& headerJson)
{
    Header ret;
    const nlohmann::json::object_t* headerObj =
        headerJson.get_ptr<const nlohmann::json::object_t*>();
    for (const auto& [key, value] : *headerObj)
    {
        const nlohmann::json::object_t* obj =
            value.get_ptr<const nlohmann::json::object_t*>();
        if (key == "severity")
        {
            if (obj != nullptr)
            {
                for (const auto& [key, value] : *obj)
                {
                    readStrKey("name", key, value, ret.severity);
                    readIntKey("code", key, value, ret.code);
                }
            }
        }
        else if (key == "notificationType")
        {
            if (obj != nullptr)
            {
                for (const auto& [key, value] : *obj)
                {
                    readStrKey("guid", key, value, ret.notificationType);
                }
            }
        }
        else if (key == "timestamp")
        {
            readStrKey("timestamp", key, value, ret.time);
        }
    }
    return ret;
}

/*
 *  Parses libcper output to generate dbus-formatted message
 *  Arguments:
 *  1. dumpMap: Map containing CPER sections to dump on dbus
 *  Return:
 *  Number of sections parsed, CPER_PARSE_ERROR on error, CPER_PARSE_EMPTY on 0
 */
void CPER::prepareToLog(properties& dumpMap) const
{
    if (!isValid())
    {
        lg2::error("CPER is invalid");
        return;
    }

    auto sectionDescriptors = jsonData.find("sectionDescriptors");
    if (sectionDescriptors == jsonData.end())
    {
        lg2::error("Section Descriptor property not found in CPER log");
        return;
    }

    const nlohmann::json::array_t* sectionDs =
        sectionDescriptors->get_ptr<const nlohmann::json::array_t*>();
    if (sectionDs == nullptr)
    {
        lg2::error("Section Descriptor property is not an array");
        return;
    }
    auto sectionD = sectionDs->begin();

    auto sections = jsonData.find("sections");
    if (sections == jsonData.end())
    {
        lg2::error("Sections property not found in CPER log");
        return;
    }
    const nlohmann::json::array_t* sectionArrs =
        sections->get_ptr<const nlohmann::json::array_t*>();
    if (sectionArrs == nullptr)
    {
        lg2::error("Sections property is not an array");
        return;
    }
    auto sectionArr = sectionArrs->begin();

    // Ensure sections and sectionDescriptors are same sized arrays
    if (sectionArrs->size() != sectionDs->size())
    {
        lg2::error("Invalid CPER: Number of Sections and Section Descriptors "
                   "do not match");
        return;
    }

    Header header;
    const auto headerJson = jsonData.find("header");
    std::map<std::string, std::string> commonProps;

    if (headerJson == jsonData.end())
    {
        lg2::error("Absent header field, proceeding as a section log");
        // single-section CPER
        commonProps["diagnosticDataType"] = "CPERSection";
    }
    else
    {
        // full CPER
        commonProps["diagnosticDataType"] = "CPER";
        header = readHeader(*headerJson);
        commonProps["cperSeverity"] = header.severity;
        commonProps["cperSeverityCode"] = std::to_string(header.code);
        commonProps["notificationType"] = header.notificationType;
        if (!header.time.empty())
        {
            commonProps["timestamp"] = header.time;
        }
    }

    // Iterate over sections
    for (size_t logCountInd = 0; logCountInd < sectionDs->size(); logCountInd++)
    {
        nlohmann::json out;

        auto& entry = dumpMap.emplace_back();
        for (const auto& [key, value] : commonProps)
        {
            entry[key] = value;
        }

        entry["diagnosticData"] = toBase64String(this->cperData);
        entry["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";

        if (constructDiagnosticData(out, *sectionD, *sectionArr))
        {
            lg2::error("Could not construct CPER data for section.");
        }
        entry["jsonDiagnosticData"] = out.dump(4, ' ');

        // sectionDescriptor has the CPER's severity & sectionType

        std::string stype =
            sectionD->value("/sectionType/data"_json_pointer, "");
        if (stype.empty())
        {
            lg2::error("sectionType property not found");
        }
        else
        {
            entry["sectionType"] = stype;
        }

        sectionD++;
        sectionArr++;
    }
}

// Callback function
static void asioCallback(const boost::system::error_code& ec,
                         sdbusplus::message::message& msg)
{
    if (ec)
    {
        lg2::error("Error in callback {1}", "1", msg.get_errno());
    }
}

// Log to sdbus
void CPER::log(const std::map<std::string, std::string>& props,
               sdbusplus::asio::connection& conn) const
{
    std::map<std::string, std::variant<std::string, uint64_t>> dumpData;
    std::string cperSeverity;

    for (const auto& pair : props)
    {
        lg2::debug("{1}: {2}", "1", pair.first, "2", pair.second);
        if ("diagnosticDataType" == pair.first)
        {
            dumpData["CPER_PATH"] = this->cperPath;
            dumpData["CPER_TYPE"] = pair.second;
        }
        if ("cperSeverity" == pair.first)
        {
            cperSeverity = pair.second;
        }
    }

    // Send to phosphor-logging
    conn.async_method_call(
        // callback
        asioCallback,
        // dbus method: service, object, interface, method
        "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
        "xyz.openbmc_project.Logging.Create", "Create",
        // parameters: ssa{ss}
        "A CPER was logged", toDbusSeverity(cperSeverity), props);
}

// Private funtions

// Load json from file
#ifdef CPER_LOGGER_DEBUG_TRACE
void CPER::readJsonFile(const std::string& filename)
{
    std::ifstream jsonFile(filename.c_str());

    if (!jsonFile.is_open())
    {
        lg2::error("Failed reading {1} as json", "1", filename);
        return;
    }

    this->jsonData = nlohmann::json::parse(jsonFile, nullptr, false);
}
#endif

void CPER::readPldmData(std::span<const unsigned char> pldmData)
{
    const size_t pldmHeaderSize = 4;
    const size_t sectionDescriptorSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

    // 1st 4 bytes are a PLDM header, and there needs to be at least 1
    // section-descriptor
    if (pldmData.size() < pldmHeaderSize + sectionDescriptorSize)
    {
        lg2::error("Invalid CPER: Got {1} bytes", "1", pldmData.size());
        return;
    }

    // 0:Full CPER (header & sections), 1:Single section (no header)
    uint8_t type = pldmData[1];
    if (type > 1)
    {
        lg2::error("Invalid CPER: Got format-type {1}", "1", type);
        return;
    }

    // copy the CPER binary for encoding later
    cperData.assign(pldmData.begin() + pldmHeaderSize, pldmData.end());
    std::cout << "cperData " << std::to_string(cperData.size()) << "\n";
    // parse to json as char* from libcper
    char* raw = nullptr;
    if (type)
    {
        raw =
            cperbuf_single_section_to_str_ir(cperData.data(), cperData.size());
    }
    else
    {
        raw = cperbuf_to_str_ir(cperData.data(), cperData.size());
    }
    if (raw == nullptr)
    {
        lg2::error("Failed parsing cper data");
        return;
    }
    std::unique_ptr<char, void (*)(void*)> jstr(raw, free);
    this->jsonData = nlohmann::json::parse(jstr.get(), nullptr, false);
}

// conversion
// ... to dbus-sevrity
std::string CPER::toDbusSeverity(const std::string& severity) const
{
    if ("Recoverable" == severity)
    {
        return "xyz.openbmc_project.Logging.Entry.Level.Warning";
    }
    if ("Fatal" == severity)
    {
        return "xyz.openbmc_project.Logging.Entry.Level.Critical";
    }
    if ("Corrected" == severity || "Informational" == severity)
    {
        return "xyz.openbmc_project.Logging.Entry.Level.Informational";
    }
    return "xyz.openbmc_project.Logging.Entry.Level.Warning";
}

// ... to base64
std::string CPER::toBase64String(const std::vector<uint8_t>& data) const
{
    // encoded_size() doesn't include \0
    size_t len = boost::beast::detail::base64::encoded_size(data.size()) + 1;
    std::string encoded(len, '\0');

    size_t written = boost::beast::detail::base64::encode(
        encoded.data(), data.data(), data.size());
    encoded.resize(written);

    return encoded;
}
