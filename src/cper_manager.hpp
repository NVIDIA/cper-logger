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

#pragma once

#include "cper_entry.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace phosphor::cper
{

// Manages persistent CPER storage and the corresponding D-Bus entry objects.
//
// Responsibilities:
//   - Write each incoming CPER to <storageDir>/<id>.bin (raw PLDM data).
//   - Create a CperEntry D-Bus object for each stored record.
//   - On construction, scan the storage directory and recreate entries for any
//     files that survived a previous run.
//   - Enforce a maximum entry count and a maximum total on-disk size; evict the
//     oldest entry (lowest id) when either limit would be exceeded.
class Manager
{
  public:
    static constexpr size_t kDefaultMaxEntries = 100;
    static constexpr size_t kDefaultMaxBytes = 100ULL * 1024; // 100 KB

    Manager(sdbusplus::asio::object_server& server,
            const std::string& storageDir,
            size_t maxEntries = kDefaultMaxEntries,
            size_t maxTotalBytes = kDefaultMaxBytes);

    // Save rawPldmData to disk and create a D-Bus entry.
    // commonProps is from section 0 of prepareToLog(); fullJson is the
    // complete libcper JSON for the CPER record.
    void store(const std::vector<uint8_t>& rawPldmData,
               const std::map<std::string, std::string>& commonProps,
               const nlohmann::json& fullJson);

  private:
    void loadExisting();
    // Evicts oldest entries until the configured limits are satisfied.
    // incomingBytes > 0 means an entry of that size is about to be inserted,
    // so a slot is reserved for it (being exactly at maxEntries evicts one).
    // incomingBytes == 0 means nothing is pending (e.g. startup reconciliation
    // in loadExisting()), so only genuine excess over maxEntries is evicted.
    // Returns false if eviction got stuck (a file couldn't be removed) while
    // limits were still exceeded; callers that are about to insert should
    // treat false as "don't insert" rather than let the limit be blown.
    bool enforceCapacity(size_t incomingBytes);
    // Removes the oldest tracked entry. No-op if the on-disk file can't be
    // deleted, so callers must detect non-progress to avoid looping forever.
    bool removeOldest();
    // Deletes an on-disk file that loadExisting() could not turn into a
    // tracked entry, so it doesn't leak disk space forever.
    void removeUnloadable(const std::filesystem::path& path,
                      const std::string& reason);

    std::filesystem::path entryPath(uint64_t id) const;
    size_t totalStorageBytes() const;

    sdbusplus::asio::object_server& server;
    std::filesystem::path storageDir;
    size_t maxEntries;
    size_t maxTotalBytes;

    // Ordered by id; lowest id == oldest entry.
    std::map<uint64_t, std::shared_ptr<CperEntry>> entries;
    // Actual on-disk path per entry (may differ from entryPath() for legacy files).
    std::map<uint64_t, std::filesystem::path> filePaths;
    uint64_t nextId = 0;
};

} // namespace phosphor::cper
