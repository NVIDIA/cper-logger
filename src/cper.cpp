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

// Convert to logging
void CPER::prepareToLog(properties& m) const
{
    const nlohmann::json& cper = this->jsonData;
    const auto& header = cper.find("header");

    if (!isValid())
    {
        // unknown CPER - use some defaults
        m["diagnosticDataType"] = "CPER";
        m["cperSeverity"] = "Unknown";
    }
    else if (cper.end() == header)
    {
        // single-section CPER
        m["diagnosticDataType"] = "CPERSection";

        // sectionDescriptor has the CPER's severity & sectionType
        if ((!cper.value("/sectionDescriptor/severity/name"_json_pointer,
                         nlohmann::json())
                  .empty()) &&
            (!cper.value("/sectionDescriptor/sectionType/data"_json_pointer,
                         nlohmann::json())
                  .empty()))
        {
            m["cperSeverity"] =
                cper["/sectionDescriptor/severity/name"_json_pointer];
            m["notificationType"] =
                cper["/sectionDescriptor/sectionType/data"_json_pointer];
        }
        else
        {
            lg2::error("Invalid full CPER {1}", "1", this->cperPath);
            return;
        }
    }
    else
    {
        // full CPER
        m["diagnosticDataType"] = "CPER";

        // header has the CPER's severity & notificationType
        if ((!cper.value("/header/severity/name"_json_pointer, nlohmann::json())
                  .empty()) &&
            (!cper.value("/header/notificationType/guid"_json_pointer,
                         nlohmann::json())
                  .empty()))
        {
            m["cperSeverity"] = cper["/header/severity/name"_json_pointer];
            m["notificationType"] =
                cper["/header/notificationType/guid"_json_pointer];
        }
        else
        {
            lg2::error("Invalid full CPER {1}", "1", this->cperPath);
            return;
        }
    }

    if (isValid())
    {
        auto jStr = cper.dump();
        jStr.erase(std::remove(jStr.begin(), jStr.end(), '='), jStr.end());
        m["jsonDiagnosticData"] = jStr;
    }

    if (!this->cperData.empty())
    {
        m["diagnosticData"] = toBase64String(this->cperData);
    }

    m["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";
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
void CPER::log(const properties& m, sdbusplus::asio::connection& conn) const
{
    std::map<std::string, std::variant<std::string, uint64_t>> dumpData;
    std::string cperSeverity;

    for (const auto& pair : m)
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
        "A CPER was logged", toDbusSeverity(cperSeverity), m);

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
