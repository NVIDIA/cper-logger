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

#include <cper-parse-str.h>

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
#include <edk/Cper.h>
}

// Public functions
int constructDiagnosticData(nlohmann::json& out, const nlohmann::json& hdr,
                            const auto secdIt, const auto secIt,
                            const uint64_t idx)
{

    if (secdIt == nullptr || secIt == nullptr)
    {
        lg2::error("Section Descriptor and Section ptrs are null");
        return -1;
    }

    out["sectionDescriptors"] = nlohmann::json::array({(*secdIt)[idx]});
    out["sections"] = nlohmann::json::array({(*secIt)[idx]});

    if (!hdr.empty())
    {
        out["header"] = hdr;
    }
    return 0;
}

// Constructor from file
CPER::CPER(const std::string& filename) : cperPath(filename)
{
    readPldmFile(filename);

#ifdef CPER_LOGGER_DEBUG_TRACE
    if (this->jsonData.empty() || this->jsonData.is_discarded())
    {
        // Debug-mode - Try the incoming file as json
        readJsonFile(filename);
    }
#endif
    this->jsonValid =
        !(this->jsonData.empty() || this->jsonData.is_discarded());
}

void CPER::addDumpDefaults(std::map<std::string, std::string>& log) const
{
    log["diagnosticData"] = toBase64String(this->cperData);
    log["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";

    // override these defaults
    log["diagnosticDataType"] = "CPER";
    log["cperSeverity"] = "Unknown";
}

/*
 *  Parses libcper output to generate dbus-formatted message
 *  Arguments:
 *  1. dumpMap: Map containing CPER sections to dump on dbus
 *  Return:
 *  Number of sections parsed, CPER_PARSE_ERROR on error, CPER_PARSE_EMPTY on 0
 */
int CPER::prepareToLog(properties& dumpMap) const
{
    if (this->cperData.empty())
    {
        lg2::error("Empty CPER Data");
        return CPER_PARSE_ERROR;
    }

    uint64_t logCountInd = 0;
    addDumpDefaults(dumpMap[logCountInd]);

    if (!isValid())
    {
        lg2::error("CPER is invalid");
        return logCountInd + 1;
    }

    const nlohmann::json& cper = this->jsonData;

    auto sectionDescriptors = cper.find("sectionDescriptors");
    if (sectionDescriptors == cper.end())
    {
        lg2::error("Section Descriptor property not found in CPER log");
        return logCountInd + 1;
    }

    const nlohmann::json::array_t* sectionDs =
        sectionDescriptors->get_ptr<const nlohmann::json::array_t*>();
    if (sectionDs == nullptr)
    {
        lg2::error("Section Descriptor property is not an array");
        return logCountInd + 1;
    }
    const size_t numSec = sectionDs->size();

    auto sections = cper.find("sections");
    if (sections == cper.end())
    {
        lg2::error("Sections property not found in CPER log");
        return logCountInd + 1;
    }
    const nlohmann::json::array_t* sectionArr =
        sections->get_ptr<const nlohmann::json::array_t*>();
    if (sectionArr == nullptr)
    {
        lg2::error("Sections property is not an array");
        return logCountInd + 1;
    }

    // Ensure sections and sectionDescriptors are same sized arrays
    if (sectionArr->size() != numSec)
    {
        lg2::error("Invalid CPER: Number of Sections and Section Descriptors "
                   "do not match");
        return logCountInd + 1;
    }

    bool headerPresent = 0;
    nlohmann::json cperHeader, headerName, headerCode, headerData;
    const auto header = cper.find("header");
    if (cper.end() != header)
    {
        headerPresent = 1;
        cperHeader = *header;
        // header has the CPER's severity & notificationType
        headerName =
            cperHeader.value("/severity/name"_json_pointer, nlohmann::json());
        headerCode =
            cperHeader.value("/severity/code"_json_pointer, nlohmann::json());
        headerData = cperHeader.value("/notificationType/guid"_json_pointer,
                                      nlohmann::json());

        // Invalid header fields
        if (headerName.empty() || headerCode.empty() || headerData.empty())
        {
            lg2::error("Invalid header fields in full CPER {1}", "1",
                       this->cperPath);
            return logCountInd + 1;
        }
    }
    else
    {
        lg2::error("Absent header field, proceeding as a section log");
    }

    // Iterate over sections
    for (; logCountInd < numSec; logCountInd++)
    {
        nlohmann::json out;
        addDumpDefaults(dumpMap[logCountInd]);
        if (constructDiagnosticData(out, cperHeader, sectionDs, sectionArr,
                                    logCountInd))
        {
            lg2::error("Could not construct CPER data for section {1}", "1",
                       logCountInd);
            continue;
        }
        std::string jStr = out.dump();
        jStr.erase(std::remove(jStr.begin(), jStr.end(), '='), jStr.end());
        dumpMap[logCountInd]["jsonDiagnosticData"] = jStr;

        if (!headerPresent)
        {
            // single-section CPER
            dumpMap[logCountInd]["diagnosticDataType"] = "CPERSection";

            // sectionDescriptor has the CPER's severity & sectionType
            nlohmann::json name = (*sectionDs)[logCountInd].value(
                "/severity/name"_json_pointer, nlohmann::json());
            nlohmann::json code = (*sectionDs)[logCountInd].value(
                "/severity/code"_json_pointer, nlohmann::json());
            nlohmann::json data = (*sectionDs)[logCountInd].value(
                "/notificationType/data"_json_pointer, nlohmann::json());
            if (!name.empty() && !code.empty() && !data.empty())
            {
                dumpMap[logCountInd]["cperSeverity"] = name;
                dumpMap[logCountInd]["cperSeverityCode"] = to_string(code);
                dumpMap[logCountInd]["notificationType"] = data;
            }
            else
            {
                lg2::error("Invalid full CPER {1}", "1", this->cperPath);
                continue;
            }
        }

        else
        {
            // full CPER
            dumpMap[logCountInd]["diagnosticDataType"] = "CPER";

            dumpMap[logCountInd]["cperSeverity"] = to_string(headerName);

            dumpMap[logCountInd]["cperSeverityCode"] = to_string(headerCode);

            dumpMap[logCountInd]["notificationType"] = headerData;
        }

        // sectionDescriptor has the CPER's severity & sectionType
        nlohmann::json stype = (*sectionDs)[logCountInd].value(
            "/sectionType/data"_json_pointer, nlohmann::json());
        if (!stype.empty())
        {
            dumpMap[logCountInd]["sectionType"] = stype;
        }
        else
        {
            lg2::error("sectionType property not found");
            continue;
        }
    }
    return logCountInd;
}

// Callback function
static void asioCallback(const boost::system::error_code& ec,
                         sdbusplus::message::message& msg)
{
    if (ec)
    {
        lg2::error("Error {1}", "1", msg.get_errno());
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

    // Legacy: Also send to dump-manager
    if (!dumpData.empty())
    {
        conn.async_method_call(
            // callback
            asioCallback,
            // dbus method: service, object, interface, method
            "xyz.openbmc_project.Dump.Manager",
            "/xyz/openbmc_project/dump/faultlog",
            "xyz.openbmc_project.Dump.Create", "CreateDump",
            // parameters: a{sv}
            dumpData);
    }
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

void CPER::readPldmFile(const std::string& filename)
{
    const size_t pldmHeaderSize = 4;
    const size_t sectionDescriptorSize = sizeof(EFI_ERROR_SECTION_DESCRIPTOR);

    // read the file into buffer
    boost::beast::error_code ec;
    boost::beast::file_posix cperFile;
    cperFile.open(filename.c_str(), boost::beast::file_mode::read, ec);
    if (ec || !cperFile.is_open())
    {
        lg2::error("Failed opening {1}", "1", filename);
        return;
    }

    const std::streamsize pldmMaxSize = 64 << 10;
    std::vector<uint8_t> pldmData(pldmMaxSize);

    size_t bytesRead = cperFile.read(reinterpret_cast<char*>(pldmData.data()),
                                     pldmData.size(), ec);
    if (ec)
    {
        lg2::error("Failed reading {1}", "1", filename);
        return;
    }

    cperFile.close(ec);
    if (ec)
    {
        lg2::warning("Failed closing {1}", "1", filename);
        // Ignore error
    }

    pldmData.resize(bytesRead);

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

    size_t len = le16toh(pldmData[3] << 8 | pldmData[2]);
    if (pldmData.size() - pldmHeaderSize < len)
    {
        lg2::error("Invalid CPER: Got length {1}", "1", len);
        return;
    }

    // copy the CPER binary for encoding later
    this->cperData.assign(pldmData.begin() + pldmHeaderSize, pldmData.end());

    // parse to json as char* from libcper
    std::unique_ptr<char, void (*)(void*)> jstr(
        type ? cperbuf_single_section_to_str_ir(this->cperData.data(),
                                                this->cperData.size())
             : cperbuf_to_str_ir(this->cperData.data(), this->cperData.size()),
        free);
    if (nullptr == jstr)
    {
        lg2::error("Failed parsing cper data");
        return;
    }

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
