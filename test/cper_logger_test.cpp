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

TEST(CPERTests, GoodParseCCPLEX)
{
    const auto file =
        writeTempfile(nvidia_ccplex_good_cper, nvidia_ccplex_good_cper_len,
                      "nvidia-ccplex-good");

    CPER cp(file.c_str());
    ASSERT_TRUE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Corrected");
    EXPECT_EQ(prop["SectionType"], "NVIDIA");
    EXPECT_EQ(prop["SectionSeverity"], "Corrected");
    EXPECT_EQ(prop["NvSignature"], "CCPLEXSCF");
    EXPECT_EQ(prop["NvSeverity"], "Corrected");
    EXPECT_EQ(prop["NvSocket"], "0");
}

TEST(CPERTests, GoodParsePCIe)
{
    const auto file =
        writeTempfile(pcie_good_cper, pcie_good_cper_len, "pcie-good");

    CPER cp(file.c_str());
    ASSERT_TRUE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Corrected");
    EXPECT_EQ(prop["SectionType"], "PCIe");
    EXPECT_EQ(prop["SectionSeverity"], "Corrected");
}

TEST(CPERTests, FailParse)
{
    const auto file =
        writeTempfile(nvidia_ccplex_bad_cper, nvidia_ccplex_bad_cper_len,
                      "nvidia-ccplex-bad");

    CPER cp(file.c_str());
    ASSERT_FALSE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Unknown");
    EXPECT_EQ(prop["SectionType"], "");
}

TEST(CPERTests, MultiSeverity)
{
    const auto file = writeTempfile(nvidia_ccplex_multiseverity_cper,
                                    nvidia_ccplex_multiseverity_cper_len,
                                    "nvidia-ccplex-multiseverity");

    CPER cp(file.c_str());
    ASSERT_TRUE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Corrected");
    EXPECT_EQ(prop["SectionType"], "NVIDIA");
    EXPECT_EQ(prop["SectionSeverity"], "Fatal");
    EXPECT_EQ(prop["NvSignature"], "CCPLEXSCF");
    EXPECT_EQ(prop["NvSeverity"], "Fatal");
    EXPECT_EQ(prop["NvSocket"], "0");
}

TEST(CPERTests, NullSection)
{
    const auto file = writeTempfile(nvidia_ccplex_nullsection_cper,
                                    nvidia_ccplex_nullsection_cper_len,
                                    "nvidia-ccplex-nullsection");

    CPER cp(file.c_str());
    ASSERT_TRUE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    // This is a BUG with this CPER
    EXPECT_EQ(prop["CPERSeverity"], "Corrected");
    EXPECT_EQ(prop["SectionType"], "NVIDIA");
    EXPECT_EQ(prop["SectionSeverity"], "Corrected");
    EXPECT_EQ(prop["NvSignature"], "CCPLEXSCF");
    EXPECT_EQ(prop["NvSeverity"], "Corrected");
    EXPECT_EQ(prop["NvSocket"], "0");
}

TEST(CPERTests, MissingFile)
{
    CPER cp("/tmp/made-up-name");
    ASSERT_FALSE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Unknown");
    EXPECT_EQ(prop["SectionType"], "");
}

TEST(CPERTests, NotAFile)
{
    CPER cp("/tmp");
    ASSERT_FALSE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Unknown");
}

TEST(CPERTests, EmptyFile)
{
    CPER cp("/dev/null");
    ASSERT_FALSE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Unknown");
}

TEST(CPERTests, HugeFile)
{
    CPER cp("/dev/urandom");
    ASSERT_FALSE(cp.isValid());

    auto prop = cp.getProperties();
    EXPECT_EQ(prop["DiagnosticDataType"], "CPER");
    EXPECT_EQ(prop["CPERSeverity"], "Unknown");
}

int main()
{
    ::testing::InitGoogleTest();
    return RUN_ALL_TESTS();
}
