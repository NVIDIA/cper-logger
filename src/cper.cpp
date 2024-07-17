#include <iostream>
#include <fstream>

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>

extern "C"
{
#include <cper-parse.h>
}
#include <libbase64.h>

#include "cper.hpp"

static const nlohmann::json invalidJson = \
             nlohmann::json::parse("{invalid json}", nullptr, false);

// Public functions

// Constructor from file
CPER::CPER(const std::string& filename)
    : jsonData(invalidJson)
{
    readJsonFile(filename);

    if (jsonData.is_discarded())
        readPldmFile(filename);

    this->isValid = ! this->jsonData.is_discarded();

    prepareToLog();
}

// Find functions
// ... find object
const nlohmann::json&
CPER::findObject(const nlohmann::json& data, const std::string& key) const
{
    const auto iter = data.find(key);
    if (iter != data.end())
        return *iter;

    return invalidJson;
}

// .. find array
const nlohmann::json&
CPER::findArray(const nlohmann::json& data, const std::string& key) const
{
    const nlohmann::json& array = findObject(data, key);
    if (! array.is_discarded() && array.is_array())
        return array;

    return invalidJson;
}

// Log
void
CPER::log() const
{
    for (const auto& pair : additionalData)
    {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }

    // Shared context
    extern std::shared_ptr<sdbusplus::asio::connection> conn;

    conn->async_method_call(
        // callback
        [](boost::system::error_code ec, sdbusplus::message::message& msg)
        {
            std::cerr << "Response" << std::endl;
            std::cerr << ec << std::endl;
            if(!ec)
            {
                std::cout << "Success " << std::endl;
            }
            else
            {
                std::cerr << "Error " << msg.get_errno() << std::endl;
            }
        },
        // dbus method: service, object, interface, method
        "xyz.openbmc_project.Logging", "/xyz/openbmc_project/logging",
        "xyz.openbmc_project.Logging.Create", "Create",
        // parameters: ssa{ss}
        "CPER logged", toDbusSeverity(this->cperSeverity), additionalData
    );
}

// Private funtions

// Load json from file
void
CPER::readJsonFile(const std::string& filename)
{
    std::ifstream jsonFile(filename.c_str());

    if (jsonFile.is_open())
        this->jsonData = nlohmann::json::parse(jsonFile, nullptr, false);
}

void
CPER::readPldmFile(const std::string& filename)
{
#pragma pack(push, 1)
    typedef struct _pldm_header
    {
        uint8_t format_version;
        uint8_t format_type;
        uint16_t data_length;
    } pldm_header;
#pragma pack(pop)

    json_object* jobj = nullptr;

    // read the file into buffer
    std::cout << "Reading: " << filename << std::endl;
    std::ifstream cperFile(filename.c_str(), std::ios::binary);

    if (cperFile.is_open())
    {
        std::vector<uint8_t> pldm_data((std::istreambuf_iterator<char>(cperFile)),
                                        std::istreambuf_iterator<char>());

        std::cout << "Read bytes: " << pldm_data.size() << std::endl;

        // 1st 4 bytes are a PLDM header
        const pldm_header* hdr = (pldm_header*)(&pldm_data[0]);

        if (pldm_data.size() >= sizeof(*hdr))
        {
            int len = le16toh(hdr->data_length);

            std::cout << "Format Type: " << (int)hdr->format_type << std::endl;
            std::cout << "Data Length: " << len << std::endl;

            this->cperData.assign(pldm_data.begin() + sizeof(*hdr), pldm_data.end());

            // skip the pldm_header & create a FILE* for libcper
            FILE* file = fmemopen(&this->cperData[0], len, "r");

            // 0:Full CPER (with Header & multiple Sections), 1:Single section (no Header)
            if (0 == hdr->format_type)
                jobj = cper_to_ir(file);
            else if (1 == hdr->format_type)
                jobj = cper_single_section_to_ir(file);
            else
                std::cerr << "Ignoring file" << std::endl;

            if (nullptr != jobj)
            {
                this->jsonData = nlohmann::json::parse(json_object_to_json_string(jobj),
                                                       nullptr, false);
            }
        }
    }
}

// convert to logging
// ... header
void
CPER::convertHeader(const nlohmann::json& header)
{
    if (! this->isValid)
        return;

    const nlohmann::json& type = findObject(header, "notificationType");
    if (! type.is_discarded())
    {
        additionalData["NotificationTypeGUID"] = type.value("guid", "Not Available");
        additionalData["NotificationType"] = type.value("type", "Unknown");
    }

    const nlohmann::json& severity = findObject(header, "severity");
    if (! severity.is_discarded())
    {
        this->cperSeverity = severity.value("name", "Unknown");
        additionalData["CPERSeverity"] = this->cperSeverity;
    }

    const nlohmann::json& count = findObject(header, "sectionCount");
    if (! count.is_discarded())
        additionalData["SectionCount"] = count.dump();
}

// .. sectionDescriptor
void
CPER::convertSectionDescriptor(const nlohmann::json& desc)
{
    if (! this->isValid)
        return;

    const nlohmann::json& type = findObject(desc, "sectionType");
    if (! type.is_discarded())
    {
        this->sectionType = type.value("type", "Unknown");

        additionalData["SectionTypeGUID"] = type.value("data", "Not Available");
        additionalData["SectionType"] = this->sectionType;
    }

    const nlohmann::json& severity = findObject(desc, "severity");
    if (! severity.is_discarded())
        additionalData["SectionSeverity"] = severity.value("name", "Unknown");

    const nlohmann::json& fru = findObject(desc, "fruID");
    if (! fru.is_discarded())
        additionalData["FruID"] = fru.get<std::string>();
}

// .. section
void
CPER::convertSection(const nlohmann::json& section)
{
    if (! this->isValid)
        return;

    if ("NVIDIA" == this->sectionType)
        convertSectionNVIDIA(section);
    else if ("PCIe" == this->sectionType)
        convertSectionPCIe(section);
}

// ... PCIe section
void
CPER::convertSectionPCIe(const nlohmann::json& section)
{
    if (! this->isValid || "PCIe" != this->sectionType)
        return;

    const nlohmann::json& pciId = findObject(section, "deviceID");
    if (! pciId.is_discarded())
    {
        additionalData["PCIeVendorId"] = toHexString(pciId.value("vendorID", -1), 4);
        additionalData["PCIeDeviceId"] = toHexString(pciId.value("deviceID", -1), 4);
        additionalData["PCIeClassCode"] = toHexString(pciId.value("classCode", -1), 6);
        additionalData["PCIeFunctionNumber"] = toHexString(pciId.value("functionNumber", -1), 2);
        additionalData["PCIeDeviceNumber"] = toHexString(pciId.value("deviceNumber", -1), 2);
        additionalData["PCIeSegmentNumber"] = toHexString(pciId.value("segmentNumber", -1), 4);
        additionalData["PCIeDeviceBusNumber"] = toHexString(pciId.value("primaryOrDeviceBusNumber", -1), 2);
        additionalData["PCIeSecondaryBusNumber"] = toHexString(pciId.value("secondaryBusNumber", -1), 2);
        additionalData["PCIeSlotNumber"] = toHexString(pciId.value("slotNumber", -1), 4);
    }
}

// ... NVIDIA section
void
CPER::convertSectionNVIDIA(const nlohmann::json& section)
{
    if (! this->isValid || "NVIDIA" != this->sectionType)
        return;

    additionalData["NvSignature"] = section.value("signature", "Unknown");
    additionalData["NvSeverity"] = toNvSeverity(section.value("severity", -1));

    const nlohmann::json& nvSocket = findObject(section, "socket");
    if (! nvSocket.is_discarded())
        additionalData["NvSocket"] = nvSocket.dump();

}

// ... CPER
void
CPER::prepareToLog()
{
    const nlohmann::json& cper = this->jsonData;
    const nlohmann::json& hdr = findObject(cper, "header");

    if (cper.is_discarded())
    {
        // unknown CPER - use some defaults
        additionalData["DiagnosticDataType"] = "CPER";
        additionalData["CPERSeverity"] = "Unknown";
    }
    else if (hdr.is_discarded())
    {
        // single-section CPER
        additionalData["DiagnosticDataType"] = "CPERSection";

        const nlohmann::json& desc = findObject(cper, "sectionDescriptor");
        convertSectionDescriptor(desc);

        const nlohmann::json& section = findObject(cper, "section");
        convertSection(section);
    }
    else
    {
        // full CPER
        additionalData["DiagnosticDataType"] = "CPER";

        convertHeader(hdr);

        const nlohmann::json& descs = findArray(cper, "sectionDescriptors");
        const nlohmann::json& sections = findArray(cper, "sections");

        size_t count = hdr.value("sectionCount", 0);
        size_t worst = findWorst(descs, sections, count);

        if (descs.size() > worst)
            convertSectionDescriptor(descs[worst]);
        if (sections.size() > worst)
            convertSection(sections[worst]);
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

    // sanity checks
    if (! this->isValid ||
        descs.is_discarded() || ! descs.is_array() || descs.empty() ||
        sections.is_discarded() || ! sections.is_array() || sections.empty() ||
        descs.size() < nelems)
        return ret;

    // uninitialized value to start
    int worst = -1;

    int i = 0;
    auto desc_it = descs.begin();
    auto section_it = sections.begin();
    while (desc_it != descs.end() && section_it != sections.end())
    {
        const auto& desc = *desc_it;
        const auto& section = *section_it;

        // drop section if anything is not populated correctly
        if (section.is_null() || desc.is_null() ||
            0 == desc.value("sectionOffset", 0))
            continue;

        // get severity of current section-descriptor
        int sev = 3;
        const nlohmann::json& currentSev = findObject(desc, "severity");
        if (! currentSev.is_discarded())
            sev = currentSev.value("code", 3);

        // if initialized, lower rank is worse
        if (worst < 0 || sevRank[sev] < sevRank[worst])
        {
            ret = i;
            worst = sev;
        }

        ++i;
        ++desc_it;
        ++section_it;
    }

    return ret;
}

// conversion
// ... to dbus
const std::string
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
const std::string
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
const std::string
CPER::toHexString(int num, size_t width) const
{
    std::stringstream hexStr;

    hexStr << "0x" << std::hex << std::setw(width) << std::setfill('0') << num;
    return hexStr.str();
}

// ... to base64
const std::string
CPER::toBase64String(const std::vector<uint8_t>& data) const
{
    std::string encodedData;
    size_t encodedLen = 4 * ((data.size() + 2)/3);

    encodedData.resize(encodedLen);
    base64_encode(reinterpret_cast<const char*>(data.data()), data.size(), &encodedData[0], &encodedLen, 0);
    encodedData.resize(encodedLen);

    return encodedData;
}

