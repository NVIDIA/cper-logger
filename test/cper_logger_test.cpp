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

#include <fstream>
#include <iostream>

#include <gtest/gtest.h>

static auto configFile = std::ifstream("cper-logger.json");

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

void parseOut(const properties& m, const nlohmann::json& array,
              nlohmann::json& jFlat)
{
    for (const auto& item : array)
    {
        const auto& cf = item.find("from");
        const auto& ct = item.find("to");
        if (item.end() == cf || item.end() == ct)
        {
            continue;
        }

        const auto& f = m.find(*cf);
        if (m.end() == f)
        {
            continue;
        }

        const auto& cj = item.find("json");
        if (item.end() == cj || cj->get<bool>() == false)
        {
            jFlat[*ct] = f->second;
            continue;
        }

        auto prefix = ct->dump();
        prefix.erase(std::remove(prefix.begin(), prefix.end(), '\"'),
                     prefix.end());

        auto jj = nlohmann::ordered_json::parse(f->second);
        for (auto& [key, value] : jj.items())
        {
            jFlat[prefix + key] = value;
        }
    }
}

auto redfishOutput(std::ifstream& configFile, const properties& m)
{
    auto jOut = nlohmann::json::parse(R"({ })");

    configFile.seekg(0, std::ios::beg);
    const auto& config = nlohmann::ordered_json::parse(configFile);

    const auto& redfishConfig = config.find("redfishProperties");
    if (config.end() != redfishConfig)
    {
        parseOut(m, *redfishConfig, jOut);
    }

    return jOut;
}

TEST(CPERTests, GoodParseCCPLEX)
{
    const auto file =
        writeTempfile(nvidia_ccplex_good_cper, nvidia_ccplex_good_cper_len,
                      "nvidia-ccplex-good");

    properties prop;
    CPER cp(file.c_str());
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Corrected");
    const auto& rf = redfishOutput(configFile, prop);
    EXPECT_EQ(
        rf.at("/CPER/Oem/Nvidia/libcper/sectionDescriptors/0/sectionType/type"),
        "NVIDIA");
    EXPECT_EQ(rf.at("/CPER/Oem/Nvidia/libcper/sections/0/signature"),
              "CCPLEXSCF");
    EXPECT_EQ(rf.at("/CPER/NotificationType"),
              "09a9d5ac-5204-4214-96e594992e752bcd");
}

TEST(CPERTests, GoodParsePCIe)
{
    const auto file =
        writeTempfile(pcie_good_cper, pcie_good_cper_len, "pcie-good");

    properties prop;
    CPER cp(file.c_str());
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Corrected");
    const auto& rf = redfishOutput(configFile, prop);
    EXPECT_EQ(
        rf.at("/CPER/Oem/Nvidia/libcper/sectionDescriptors/0/sectionType/type"),
        "PCIe");
    EXPECT_EQ(rf.at("/CPER/NotificationType"),
              "09a9d5ac-5204-4214-96e594992e752bcd");
}

TEST(CPERTests, FailParse)
{
    const auto file =
        writeTempfile(nvidia_ccplex_bad_cper, nvidia_ccplex_bad_cper_len,
                      "nvidia-ccplex-bad");

    properties prop;
    CPER cp(file.c_str());
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Unknown");
}

TEST(CPERTests, MultiSeverity)
{
    const auto file = writeTempfile(nvidia_ccplex_multiseverity_cper,
                                    nvidia_ccplex_multiseverity_cper_len,
                                    "nvidia-ccplex-multiseverity");

    properties prop;
    CPER cp(file.c_str());
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Corrected");
    const auto& rf = redfishOutput(configFile, prop);
    EXPECT_EQ(
        rf.at("/CPER/Oem/Nvidia/libcper/sectionDescriptors/0/sectionType/type"),
        "NVIDIA");
    EXPECT_EQ(rf.at("/CPER/Oem/Nvidia/libcper/sections/0/signature"),
              "CCPLEXSCF");
    EXPECT_EQ(rf.at("/CPER/NotificationType"),
              "09a9d5ac-5204-4214-96e594992e752bcd");
}

TEST(CPERTests, NullSection)
{
    const auto file = writeTempfile(nvidia_ccplex_nullsection_cper,
                                    nvidia_ccplex_nullsection_cper_len,
                                    "nvidia-ccplex-nullsection");

    properties prop;
    CPER cp(file.c_str());
    cp.prepareToLog(prop);
    ASSERT_TRUE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    // This is a BUG with this CPER
    EXPECT_EQ(prop["cperSeverity"], "Corrected");
    const auto& rf = redfishOutput(configFile, prop);
    EXPECT_EQ(
        rf.at("/CPER/Oem/Nvidia/libcper/sectionDescriptors/0/sectionType/type"),
        "NVIDIA");
    EXPECT_EQ(rf.at("/CPER/Oem/Nvidia/libcper/sections/0/signature"),
              "CCPLEXSCF");
    EXPECT_EQ(rf.at("/CPER/NotificationType"),
              "09a9d5ac-5204-4214-96e594992e752bcd");
}

TEST(CPERTests, MissingFile)
{
    properties prop;
    CPER cp("/tmp/made-up-name");
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Unknown");
}

TEST(CPERTests, NotAFile)
{
    properties prop;
    CPER cp("/tmp");
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Unknown");
}

TEST(CPERTests, EmptyFile)
{
    properties prop;
    CPER cp("/dev/null");
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Unknown");
}

TEST(CPERTests, HugeFile)
{
    properties prop;
    CPER cp("/dev/zero");
    cp.prepareToLog(prop);
    ASSERT_FALSE(cp.isValid());

    EXPECT_EQ(prop["diagnosticDataType"], "CPER");
    EXPECT_EQ(prop["cperSeverity"], "Unknown");
}
