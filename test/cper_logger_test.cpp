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

#include "nvidia/ccplex/bad_cper.h"
#include "nvidia/ccplex/good_cper.h"
#include "nvidia/ccplex/multiseverity_cper.h"
#include "nvidia/ccplex/nullsection_cper.h"
#include "pcie/good_cper.h"

#include "cper.hpp"

#include <chrono>
#include <fstream>
#include <iostream>

#include <gtest/gtest.h>

std::string writeTempfile(const unsigned char* data, unsigned int size,
                          const std::string& basename)
{
    std::string fileName = "/tmp/" + basename + "-cper-XXXXXX";
    auto fd = mkstemp(fileName.data());
    if (fd < 0)
    {
        std::cout << "Failed creating file" << std::endl;
        return {};
    }
    close(fd);

    std::ofstream ofs;
    ofs.exceptions(std::ofstream::failbit | std::ofstream::badbit |
                   std::ofstream::eofbit);
    try
    {
        ofs.open(fileName);
        ofs.write(reinterpret_cast<const char*>(data), size);
    }
    catch (const std::exception& e)
    {
        std::cout << "Failed writing to file" << std::endl;
        return {};
    }
    return fileName;
}

struct Keypair
{
    std::string_view from;
    std::string_view to;
    bool json = false;
};

void parseOut(const std::map<std::string, std::string>& m,
              const std::span<Keypair>& array, nlohmann::json::object_t& jFlat)
{
    for (const auto& element : array)
    {
        const auto& f = m.find(std::string(element.from));
        if (m.end() == f)
        {
            continue;
        }

        bool cj = element.json;
        if (cj == false)
        {
            jFlat[std::string(element.to)] = f->second;
            continue;
        }

        std::string prefix(element.to);
        prefix.erase(std::remove(prefix.begin(), prefix.end(), '\"'),
                     prefix.end());

        auto jj = nlohmann::ordered_json::parse(f->second);
        for (auto& [key, value] : jj.items())
        {
            jFlat[prefix + key] = value;
        }
    }
}

std::vector<nlohmann::json::object_t> redfishOutput(const properties& m)
{
    std::array<Keypair, 6> redfishConfig = {
        {{"REDFISH_MESSAGE_ID", "/MessageId"},
         {"diagnosticData", "/DiagnosticData"},
         {"diagnosticDataType", "/DiagnosticDataType"},
         {"notificationType", "/CPER/NotificationType"},
         {"sectionType", "/CPER/SectionType"},
         {"jsonDiagnosticData", "/CPER/Oem/Nvidia", true}}};

    std::vector<nlohmann::json::object_t> jOut;
    for (const auto& it : m)
    {
        parseOut(it, redfishConfig, jOut.emplace_back());
    }
    return jOut;
}

TEST(CPERTests, GoodParseCCPLEX)
{
    properties prop;

    CPER cp(nvidiaCcplexGoodCper);
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop[0]["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop[0]["cperSeverity"], "Corrected");
    std::vector<nlohmann::json::object_t> rf = redfishOutput(prop);

    // std::cout << nlohmann::json(rf[2]).dump(4, ' ') << '\n';

    // TODO NEED TO ASSERT index 1-3
    ASSERT_EQ(prop.size(), 5);

    // TODO BUG
    EXPECT_EQ(
        rf[0]["/CPER/Oem/NvidiasectionDescriptors"][0]["sectionType"]["type"],
        "NVIDIA");
    EXPECT_EQ(rf[0]["/CPER/Oem/Nvidiasections"][0]["Nvidia"]["signature"],
              "CCPLEXSCF");
    EXPECT_EQ(rf[0]["/CPER/NotificationType"],
              "09a9d5ac-5204-4214-96e5-94992e752bcd");
}

TEST(CPERTests, GoodParsePCIe)
{
    properties prop;
    CPER cp(pcieGoodCper);
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop[0]["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop[0]["cperSeverity"], "Corrected");
    std::vector<nlohmann::json::object_t> rf = redfishOutput(prop);
    ASSERT_EQ(prop.size(), 1);
    EXPECT_EQ(
        rf[0]["/CPER/Oem/NvidiasectionDescriptors"][0]["sectionType"]["type"],
        "PCIe");
    EXPECT_EQ(rf[0]["/CPER/NotificationType"],
              "09a9d5ac-5204-4214-96e5-94992e752bcd");
}

TEST(CPERTests, FailParse)
{
    properties prop;
    CPER cp(nvidiaCcplexBadCper);
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());
    ASSERT_EQ(prop.size(), 0);
}

TEST(CPERTests, MultiSeverity)
{
    properties prop;
    CPER cp(nvidiaCcplexMultiseverityCper);
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    // TODO NEED TO ASSERT index 1-4
    ASSERT_EQ(prop.size(), 5);

    EXPECT_EQ(prop[0]["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop[0]["cperSeverity"], "Corrected");
    std::vector<nlohmann::json::object_t> rf = redfishOutput(prop);
    EXPECT_EQ(
        rf[0]["/CPER/Oem/NvidiasectionDescriptors"][0]["sectionType"]["type"],
        "NVIDIA");
    EXPECT_EQ(rf[0]["/CPER/Oem/Nvidiasections"][0]["Nvidia"]["signature"],
              "CCPLEXSCF");
    EXPECT_EQ(rf[0]["/CPER/NotificationType"],
              "09a9d5ac-5204-4214-96e5-94992e752bcd");
    // std::cout << nlohmann::json(rf[1]).dump(4, ' ') << '\n';
}

TEST(CPERTests, NullSection)
{
    properties prop;
    CPER cp(nvidiaCcplexNullsectionCper);
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop[0]["diagnosticDataType"], "CPER");
    // This is a BUG with this CPER
    EXPECT_EQ(prop[0]["cperSeverity"], "Corrected");
    std::vector<nlohmann::json::object_t> rf = redfishOutput(prop);

    // TODO NEED TO ASSERT index 1-3
    ASSERT_EQ(prop.size(), 4);
    EXPECT_EQ(
        rf[0]["/CPER/Oem/NvidiasectionDescriptors"][0]["sectionType"]["type"],
        "NVIDIA");
    EXPECT_EQ(rf[0]["/CPER/Oem/Nvidiasections"][0]["Nvidia"]["signature"],
              "CCPLEXSCF");
    EXPECT_EQ(rf[0]["/CPER/NotificationType"],
              "09a9d5ac-5204-4214-96e5-94992e752bcd");
}

TEST(CPERTests, AddDumpDefaults)
{
    CPER cp(nvidiaCcplexGoodCper);
    ASSERT_TRUE(cp.isValid());

    const nlohmann::json& json = cp.getJson();
    EXPECT_TRUE(json.is_object());

    std::map<std::string, std::string> logEntry;
    cp.addDumpDefaults(logEntry);

    EXPECT_EQ(logEntry["REDFISH_MESSAGE_ID"], "Platform.1.0.PlatformError");
    EXPECT_EQ(logEntry["diagnosticDataType"], "CPER");
    EXPECT_EQ(logEntry["cperSeverity"], "Unknown");
    EXPECT_FALSE(logEntry["diagnosticData"].empty());
}

TEST(CPERTests, TooSmallData)
{
    unsigned char tiny[] = {0x00};
    CPER cp(std::span<const unsigned char>(tiny, sizeof(tiny)));
    ASSERT_FALSE(cp.isValid());

    properties prop;
    cp.prepareToLog(prop);
    EXPECT_EQ(prop.size(), 0);
}

TEST(CPERTests, InvalidType)
{
    // Copy good CPER and change the PLDM format-type byte to 2 (invalid).
    std::vector<unsigned char> data(
        nvidiaCcplexGoodCper, nvidiaCcplexGoodCper + nvidiaCcplexGoodCperLen);
    data[1] = 0x02;
    CPER cp(data);
    ASSERT_FALSE(cp.isValid());

    properties prop;
    cp.prepareToLog(prop);
    EXPECT_EQ(prop.size(), 0);
}

TEST(CPERTests, LogFunction)
{
    CPER cp(nvidiaCcplexGoodCper);
    ASSERT_TRUE(cp.isValid());

    try
    {
        boost::asio::io_context io;
        sdbusplus::asio::connection conn(io);

        // Exercise all branches of toDbusSeverity
        const std::vector<std::string> severities = {
            "Recoverable", "Fatal", "Corrected", "Informational", "Unknown"};

        for (const auto& sev : severities)
        {
            std::map<std::string, std::string> props;
            props["cperSeverity"] = sev;
            props["diagnosticDataType"] = "CPER";
            cp.log(props, conn);
        }

        // Process any pending callbacks (asioCallback fires on dbus error
        // reply)
        io.run_for(std::chrono::milliseconds(100));
    }
    catch (const std::exception& e)
    {
        GTEST_SKIP() << "D-Bus not available: " << e.what();
    }
}

int main(int argc, char** argv)
{
    //  cper_set_log_stdio();
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
