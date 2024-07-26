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
    void log(const std::shared_ptr<sdbusplus::asio::connection>&) const;

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

    size_t findWorst(const nlohmann::json& descs,
                     const nlohmann::json& sections, size_t nelems) const;

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
