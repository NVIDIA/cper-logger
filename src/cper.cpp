#include <iostream>
#include <fstream>

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>

extern "C"
{
#include <cper-parse.h>
#include <libcper/base64.h>
}

#include "cper.hpp"

// Public functions

// Constructor from file
CPER::CPER(const std::string& filename)
    : cperPath(filename)
{
    readPldmFile(filename);

#ifdef CPER_LOGGER_DEBUG_TRACE
    if (this->jsonData.empty() || this->jsonData.is_discarded())
    {
        // Debug-mode - Try the incoming file as json
        readJsonFile(filename);
    }
#endif
    this->isValid = !(this->jsonData.empty() || this->jsonData.is_discarded());
    prepareToLog();
}

// Log to sdbus
void
CPER::log(std::shared_ptr<sdbusplus::asio::connection> conn) const
{
    std::map<std::string, std::variant<std::string, uint64_t>> dumpData;

    for (const auto& pair : this->additionalData)
    {
#ifdef CPER_LOGGER_DEBUG_TRACE
        std::cout << pair.first << ": " << pair.second << std::endl;
#endif
        if ("DiagnosticDataType" == pair.first)
        {
            dumpData["CPER_PATH"] = this->cperPath;
            dumpData["CPER_TYPE"] = pair.second;
        }
    }

    auto cbFn = [](const boost::system::error_code& ec, sdbusplus::message::message& msg)
        {
            if(ec)
            {
                std::cerr << "Error " << msg.get_errno() << std::endl;
            }
        };

    // Send to phosphor-logging
    conn->async_method_call(
        // callback
        cbFn,
        // dbus method: service, object, interface, method
        "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
        "xyz.openbmc_project.Logging.Create", "Create",
        // parameters: ssa{ss}
        "A CPER was logged", toDbusSeverity(this->cperSeverity), this->additionalData
    );

    // Legacy: Also send to dump-manager
    if (!dumpData.empty())
    {
        conn->async_method_call(
            // callback
            cbFn,
            // dbus method: service, object, interface, method
            "xyz.openbmc_project.Dump.Manager", "/xyz/openbmc_project/dump/faultlog",
            "xyz.openbmc_project.Dump.Create", "CreateDump",
            // parameters: a{sv}
            dumpData
        );
    }
}

// Private funtions

// Load json from file
#ifdef CPER_LOGGER_DEBUG_TRACE
void
CPER::readJsonFile(const std::string& filename)
{
    std::ifstream jsonFile(filename.c_str());

    if (!jsonFile.is_open())
    {
        std::cerr << "Failed reading as json " << filename << std::endl;
        return;
    }

    this->jsonData = nlohmann::json::parse(jsonFile, nullptr, false);
}
#endif

void
CPER::readPldmFile(const std::string& filename)
{
    const size_t pldmHeaderSize = 4;
    const size_t sectionDescriptorSize = 72;

    json_object* jobj = nullptr;

    // read the file into buffer
    std::ifstream cperFile(filename.c_str(), std::ios::binary);

    if (!cperFile.is_open())
    {
        std::cerr << "Failed reading " << filename << std::endl;
        return;
    }

    std::vector<uint8_t> pldmData((std::istreambuf_iterator<char>(cperFile)),
                                  std::istreambuf_iterator<char>());

    // 1st 4 bytes are a PLDM header, and there needs to be at least 1 section-descriptor
    if (pldmData.size() < pldmHeaderSize + sectionDescriptorSize)
    {
        std::cerr << std::format("Invalid CPER: Got {} bytes", pldmData.size()) << std::endl;
        return;
    }

    uint8_t type = pldmData[1];
    size_t len = le16toh(pldmData[3] << 8 | pldmData[2]);

    if (type > 1)
    {
        std::cerr << std::format("Invalid CPER: Got format-type {}", type) << std::endl;
        return;
    }

    if (pldmData.size() - pldmHeaderSize < len)
    {
        std::cerr << std::format("Invalid CPER: Got length {}", len) << std::endl;
        return;
    }

    // copy the CPER binary for encoding later
    this->cperData.assign(pldmData.begin() + pldmHeaderSize, pldmData.begin() + len);

    // create a FILE* for libcper
    FILE* file = fmemopen(this->cperData.data(), len, "r");

    // 0:Full CPER (with Header & multiple Sections),
    // 1:Single section (no Header)
    if (0 == type)
    {
        jobj = cper_to_ir(file);
    }
    else if (1 == type)
    {
        jobj = cper_single_section_to_ir(file);
    }

    if (nullptr != jobj)
    {
        this->jsonData = nlohmann::json::parse(json_object_to_json_string(jobj),
                                               nullptr, false);
    }
}

// convert to logging
// ... header
void
CPER::convertHeader(const nlohmann::json& header)
{
    if (!this->isValid)
    {
        std::cerr << "Invalid CPER: flagged" << std::endl;
        return;
    }

    const auto type = header.find("notificationType");
    if (type != header.end())
    {
        additionalData["NotificationTypeGUID"] = type->value("guid", "Not Available");
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
void
CPER::convertSectionDescriptor(const nlohmann::json& desc)
{
    if (!this->isValid)
    {
        std::cerr << "Invalid CPER: flagged" << std::endl;
        return;
    }

    const auto type = desc.find("sectionType");
    if (type != desc.end())
    {
        this->sectionType = type->value("type", "Unknown");
        additionalData["SectionType"] = this->sectionType;

        additionalData["SectionTypeGUID"] = type->value("data", "Not Available");
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
void
CPER::convertSection(const nlohmann::json& section)
{
    if (!this->isValid)
    {
        std::cerr << "Invalid CPER: flagged" << std::endl;
        return;
    }

    if ("NVIDIA" == this->sectionType)
    {
        convertSectionNVIDIA(section);
    }
    else if ("PCIe" == this->sectionType)
    {
        convertSectionPCIe(section);
    }
}

// ... PCIe section
void
CPER::convertSectionPCIe(const nlohmann::json& section)
{
    if (!this->isValid)
    {
        std::cerr << "Invalid CPER: flagged" << std::endl;
        return;
    }

    if ("PCIe" != this->sectionType)
    {
        std::cerr << std::format("Skipping {} section", this->sectionType) << std::endl;
        return;
    }

    const auto pciId = section.find("deviceID");
    if (pciId != section.end())
    {
        additionalData["PCIeVendorId"] = toHexString(pciId->value("vendorID", -1), 4);
        additionalData["PCIeDeviceId"] = toHexString(pciId->value("deviceID", -1), 4);
        additionalData["PCIeClassCode"] = toHexString(pciId->value("classCode", -1), 6);
        additionalData["PCIeFunctionNumber"] = toHexString(pciId->value("functionNumber", -1), 2);
        additionalData["PCIeDeviceNumber"] = toHexString(pciId->value("deviceNumber", -1), 2);
        additionalData["PCIeSegmentNumber"] = toHexString(pciId->value("segmentNumber", -1), 4);
        additionalData["PCIeDeviceBusNumber"] = toHexString(pciId->value("primaryOrDeviceBusNumber", -1), 2);
        additionalData["PCIeSecondaryBusNumber"] = toHexString(pciId->value("secondaryBusNumber", -1), 2);
        additionalData["PCIeSlotNumber"] = toHexString(pciId->value("slotNumber", -1), 4);
    }
}

// ... NVIDIA section
void
CPER::convertSectionNVIDIA(const nlohmann::json& section)
{
    if (!this->isValid)
    {
        std::cerr << "Invalid CPER: flagged" << std::endl;
        return;
    }

    if ("NVIDIA" != this->sectionType)
    {
        std::cerr << std::format("Skipping {} section", this->sectionType) << std::endl;
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
void
CPER::prepareToLog()
{
    const nlohmann::json& cper = this->jsonData;
    const auto hdr = cper.find("header");

    if (!this->isValid)
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
            std::cerr << "Invalid CPER: No sectionDescriptor" << std::endl;
            return;
        }
        convertSectionDescriptor(*desc);

        const auto section = cper.find("section");
        if (section == cper.end())
        {
            std::cerr << "Invalid CPER: No section" << std::endl;
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
            // Avoid parsing unexpectdly huge CPERs
            std::cerr << std::format("Invalid CPER: Got sectionCount {}", count) << std::endl;
            return;
        }

        const auto descs = cper.find("sectionDescriptors");
        if (descs == cper.end())
        {
            std::cerr << "Invalid CPER: No sectionDescriptors" << std::endl;
            return;
        }
        const auto sections = cper.find("sections");
        if (sections == cper.end())
        {
            std::cerr << "Invalid CPER: No sections" << std::endl;
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

    additionalData["DiagnosticData"] = toBase64String(this->cperData);
    additionalData["REDFISH_MESSAGE_ID"] = "Platform.1.0.PlatformError";
}

// utility
size_t
CPER::findWorst(const nlohmann::json& descs, const nlohmann::json& sections, size_t nelems) const
{
    // 1=Fatal > 0=Recoverable > 2=Corrected > 3=Informational
    static const int sevRank[] = { 1, 0, 2, 3 };

    int ret = 0;

    // sections can have fewer elems but section-descriptors can't
    if (!this->isValid ||
        !descs.is_array() || descs.size() < nelems ||
        !sections.is_array())
    {
        std::cerr << "Invalid CPER: cannot parse arrays" << std::endl;
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
            std::cerr << std::format("Invalid section[{}]", i) << std::endl;
            continue;
        }

        // get severity of current section-descriptor
        int sev = 3;
        const auto iter = desc->find("severity");
        if (iter != desc->end())
        {
            sev = iter->value("code", 3);
        }

        // if initialized, lower rank is worse
        if (worst < 0 || sevRank[sev] < sevRank[worst])
        {
            ret = i;
            worst = sev;
        }

        ++i;
        ++desc;
        ++section;
    }

    return ret;
}

// conversion
// ... to dbus
std::string
CPER::toDbusSeverity(const std::string& severity) const
{
    if ("Recoverable" == severity)
        return "xyz.openbmc_project.Logging.Entry.Level.Warning";
    else if ("Fatal" == severity)
        return "xyz.openbmc_project.Logging.Entry.Level.Critical";
    else if ("Corrected" == severity)
        return "xyz.openbmc_project.Logging.Entry.Level.Informational";
    else if ("Informational" == severity)
        return "xyz.openbmc_project.Logging.Entry.Level.Informational";
    else
        return "xyz.openbmc_project.Logging.Entry.Level.Warning";
}

// .. to NVIDIA
std::string
CPER::toNvSeverity(int severity) const
{
    if (0 == severity)
        return "Correctable";
    else if (1 == severity)
        return "Fatal";
    else if (2 == severity)
        return "Corrected";
    else
        return "None";
}

// ... to hex
std::string
CPER::toHexString(int num, size_t width) const
{
    std::stringstream hexStr;

    hexStr << std::format("{0:#0{1}x}", num, width);
    return hexStr.str();
}

// ... to base64
std::string
CPER::toBase64String(const std::vector<uint8_t>& data) const
{
    int encodedLen = data.size();
    char* enc = base64_encode(data.data(), data.size(), &encodedLen);

    if (nullptr == enc)
    {
        std::cerr << "Failed to encode" << std::endl;
        return std::string();
    }

    std::string encodedData = enc;
    free(enc);

    return encodedData;
}

