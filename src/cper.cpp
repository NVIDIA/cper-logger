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
    prepareToLog();
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
void CPER::log(sdbusplus::asio::connection& conn) const
{
    std::map<std::string, std::variant<std::string, uint64_t>> dumpData;

    for (const auto& pair : this->additionalData)
    {
        lg2::debug("{1}: {2}", "1", pair.first, "2", pair.second);
        if ("DiagnosticDataType" == pair.first)
        {
            dumpData["CPER_PATH"] = this->cperPath;
            dumpData["CPER_TYPE"] = pair.second;
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
        "A CPER was logged", toDbusSeverity(this->cperSeverity),
        this->additionalData);

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

// convert to logging
// ... header
void CPER::convertHeader(const nlohmann::json& header)
{
    if (!isValid())
    {
        lg2::error("Invalid CPER: flagged");
        return;
    }

    const auto type = header.find("notificationType");
    if (type != header.end())
    {
        additionalData["NotificationTypeGUID"] =
            type->value("guid", "Not Available");
        additionalData["NotificationType"] = type->value("type", "Unknown");
    }

    const auto severity = header.find("severity");
    if (severity != header.end())
    {
        this->cperSeverity = severity->value("name", "Unknown");
        additionalData["CPERSeverity"] = this->cperSeverity;
    }

    const auto count = header.find("sectionCount");
    if (count != header.end())
    {
        additionalData["SectionCount"] = count->dump();
    }
}

// .. sectionDescriptor
void CPER::convertSectionDescriptor(const nlohmann::json& desc)
{
    if (!isValid())
    {
        lg2::error("Invalid CPER: flagged");
        return;
    }

    const auto type = desc.find("sectionType");
    if (type != desc.end())
    {
        this->sectionType = type->value("type", "Unknown");
        additionalData["SectionType"] = this->sectionType;

        additionalData["SectionTypeGUID"] =
            type->value("data", "Not Available");
    }

    const auto severity = desc.find("severity");
    if (severity != desc.end())
    {
        additionalData["SectionSeverity"] = severity->value("name", "Unknown");
    }

    const auto fru = desc.find("fruID");
    if (fru != desc.end())
    {
        additionalData["FruID"] = fru->get<std::string>();
    }
}

// .. section
void CPER::convertSection(const nlohmann::json& section)
{
    if (!isValid())
    {
        lg2::error("Invalid CPER: flagged");
        return;
    }

    if ("NVIDIA" == this->sectionType)
    {
        convertSectionNVIDIA(section);
    }

    if ("PCIe" == this->sectionType)
    {
        convertSectionPCIe(section);
    }
}

// ... PCIe section
void CPER::convertSectionPCIe(const nlohmann::json& section)
{
    if (!isValid())
    {
        lg2::error("Invalid CPER: flagged");
        return;
    }

    if ("PCIe" != this->sectionType)
    {
        lg2::error("Skipping {1} section", "1", this->sectionType);
        return;
    }

    const auto pciId = section.find("deviceID");
    if (pciId != section.end())
    {
        additionalData["PCIeVendorId"] =
            toHexString(pciId->value("vendorID", -1), 4);
        additionalData["PCIeDeviceId"] =
            toHexString(pciId->value("deviceID", -1), 4);
        additionalData["PCIeClassCode"] =
            toHexString(pciId->value("classCode", -1), 6);
        additionalData["PCIeFunctionNumber"] =
            toHexString(pciId->value("functionNumber", -1), 2);
        additionalData["PCIeDeviceNumber"] =
            toHexString(pciId->value("deviceNumber", -1), 2);
        additionalData["PCIeSegmentNumber"] =
            toHexString(pciId->value("segmentNumber", -1), 4);
        additionalData["PCIeDeviceBusNumber"] =
            toHexString(pciId->value("primaryOrDeviceBusNumber", -1), 2);
        additionalData["PCIeSecondaryBusNumber"] =
            toHexString(pciId->value("secondaryBusNumber", -1), 2);
        additionalData["PCIeSlotNumber"] =
            toHexString(pciId->value("slotNumber", -1), 4);
    }
}

// ... NVIDIA section
void CPER::convertSectionNVIDIA(const nlohmann::json& section)
{
    if (!isValid())
    {
        lg2::error("Invalid CPER: flagged");
        return;
    }

    if ("NVIDIA" != this->sectionType)
    {
        lg2::error("Skipping {1} section", "1", this->sectionType);
        return;
    }

    additionalData["NvSignature"] = section.value("signature", "Unknown");
    additionalData["NvSeverity"] = toNvSeverity(section.value("severity", -1));

    const auto nvSocket = section.find("socket");
    if (nvSocket != section.end())
    {
        additionalData["NvSocket"] = nvSocket->dump();
    }
}

// ... CPER
void CPER::prepareToLog()
{
    const nlohmann::json& cper = this->jsonData;
    const auto hdr = cper.find("header");

    if (!isValid())
    {
        // unknown CPER - use some defaults
        additionalData["DiagnosticDataType"] = "CPER";
        additionalData["CPERSeverity"] = "Unknown";
    }
    else if (hdr == cper.end())
    {
        // single-section CPER
        additionalData["DiagnosticDataType"] = "CPERSection";

        const auto desc = cper.find("sectionDescriptor");
        if (desc == cper.end())
        {
            lg2::error("Invalid CPER: No sectionDescriptor");
            return;
        }
        convertSectionDescriptor(*desc);

        const auto section = cper.find("section");
        if (section == cper.end())
        {
            lg2::error("Invalid CPER: No section");
            return;
        }
        convertSection(*section);
    }
    else
    {
        // full CPER
        additionalData["DiagnosticDataType"] = "CPER";

        convertHeader(*hdr);

        size_t count = hdr->value("sectionCount", 0);
        if (count < 1 || count > 255)
        {
            lg2::error("Invalid CPER: Got sectionCount {1}", "1", count);
            return;
        }

        const auto descs = cper.find("sectionDescriptors");
        if (descs == cper.end())
        {
            lg2::error("Invalid CPER: No sectionDescriptors");
            return;
        }
        const auto sections = cper.find("sections");
        if (sections == cper.end())
        {
            lg2::error("Invalid CPER: No sections");
            return;
        }

        size_t worst = findWorst(*descs, *sections, count);

        if (descs->size() > worst)
        {
            convertSectionDescriptor((*descs)[worst]);
        }
        if (sections->size() > worst)
        {
            convertSection((*sections)[worst]);
        }
    }

    if (!this->cperData.empty())
    {
        additionalData["DiagnosticData"] = toBase64String(this->cperData);
    }
    additionalData["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";
}

// utility
size_t CPER::findWorst(const nlohmann::json::array_t& descs,
                       const nlohmann::json::array_t& sections,
                       size_t nelems) const
{
    // 1=Fatal > 0=Recoverable > 2=Corrected > 3=Informational
    static const std::array<int, 4> sevRank = {1, 0, 2, 3};

    int ret = 0;

    // sections can have fewer elems but section-descriptors can't
    if (!isValid() || descs.size() < nelems)
    {
        lg2::error("Invalid CPER: Not valid");
        return ret;
    }

    // uninitialized value to start
    int worst = -1;

    int i = 0;
    auto desc = descs.begin();
    auto section = sections.begin();
    while (desc != descs.end() && section != sections.end())
    {
        // drop section if not populated correctly
        if (0 == desc->value("sectionOffset", 0))
        {
            lg2::warning("Invalid offset for section[{1}]", "1", i);
        }
        else
        {
            // get severity of current section-descriptor
            const auto iter = desc->find("severity");
            if (iter != desc->end())
            {
                int sev = iter->value("code", 3);

                // if initialized, lower rank is worse
                if (worst < 0 || sevRank[sev] < sevRank[worst])
                {
                    ret = i;
                    worst = sev;
                }
            }
        }

        ++i;
        ++desc;
        ++section;
    }

    return ret;
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

// .. to NVIDIA-severity
std::string CPER::toNvSeverity(int severity) const
{
    // 0:Correctable, 1:Fatal, 2:Corrected, 3:None
    if (0 == severity)
    {
        return "Correctable";
    }
    if (1 == severity)
    {
        return "Fatal";
    }
    if (2 == severity)
    {
        return "Corrected";
    }
    return "None";
}

// ... to hex
std::string CPER::toHexString(int num, size_t width) const
{
    return std::format("{0:#0{1}x}", num, width);
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
