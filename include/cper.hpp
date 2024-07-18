#include <string>
#include <map>

#include <nlohmann/json.hpp>

class CPER {

public:

    // Constructor from filename
    CPER(const std::string& filename);

    // Find functions
    const nlohmann::json& findObject(const nlohmann::json& data,
                                     const std::string& key) const;
    const nlohmann::json& findArray(const nlohmann::json& data,
                                    const std::string& key) const;

    // Log
    void log() const;

private:

    // Load from libcper json
    void readJsonFile(const std::string& filename);

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

    const std::string toDbusSeverity(const std::string& severity) const;
    const std::string toNvSeverity(int severity) const;
    const std::string toHexString(int num, size_t width) const;
    const std::string toBase64String(const std::vector<uint8_t>& data) const;

private:

    // input file
    std::string cperPath;

    // from input
    nlohmann::json jsonData;
    std::vector<uint8_t> cperData;

    // saved flags
    int isValid;
    std::string cperSeverity;
    std::string sectionType;

    // for output
    std::map<std::string, std::string> additionalData;
};

