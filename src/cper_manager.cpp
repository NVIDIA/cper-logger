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

#include "cper_manager.hpp"

#include "cper.hpp"

#include <phosphor-logging/lg2.hpp>

#include <charconv>
#include <format>
#include <fstream>
#include <system_error>

namespace phosphor::cper
{

Manager::Manager(sdbusplus::asio::object_server& server,
                 const std::string& storageDirStr, size_t maxEntries,
                 size_t maxTotalBytes) :
    server(server), storageDir(storageDirStr), maxEntries(maxEntries),
    maxTotalBytes(maxTotalBytes)
{
    std::error_code ec;
    std::filesystem::create_directories(storageDir, ec);
    if (ec)
    {
        lg2::error("Failed to create CPER storage dir {DIR}: {ERR}", "DIR",
                   storageDir.string(), "ERR", ec.message());
    }

    loadExisting();
}

void Manager::store(const std::vector<uint8_t>& rawPldmData,
                    const std::map<std::string, std::string>& commonProps,
                    const nlohmann::json& fullJson)
{
    if (rawPldmData.empty())
    {
        lg2::error("Refusing to store an empty CPER payload");
        return;
    }

    if (maxEntries == 0 || rawPldmData.size() > maxTotalBytes)
    {
        lg2::error(
            "CPER payload ({SIZE} bytes) can never fit within configured limits "
            "(maxEntries={MAX_E}, maxTotalBytes={MAX_B}); dropping",
            "SIZE", rawPldmData.size(), "MAX_E", maxEntries, "MAX_B",
            maxTotalBytes);
        return;
    }

    if (!enforceCapacity(rawPldmData.size()))
    {
        lg2::error("Unable to free enough capacity for incoming CPER; dropping");
        return;
    }

    uint64_t id = nextId++;
    auto path = entryPath(id);

    // Write raw PLDM data to disk.
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f)
    {
        lg2::error("Failed to open {PATH} for writing", "PATH", path.string());
        return;
    }
    f.write(reinterpret_cast<const char*>(rawPldmData.data()),
            static_cast<std::streamsize>(rawPldmData.size()));
    f.close();

    if (!f.good())
    {
        lg2::error("Failed to write CPER data to {PATH}; removing partial file",
                   "PATH", path.string());
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return;
    }

    filePaths[id] = path;
    entries[id] = std::make_shared<CperEntry>(server, id, commonProps, fullJson,
                                              path.string());
}

// --- private -----------------------------------------------------------------

void Manager::loadExisting()
{
    std::error_code ec;
    if (!std::filesystem::exists(storageDir, ec) || ec)
    {
        return;
    }

    // Collect all <id>.bin files, sorted by id.
    std::map<uint64_t, std::filesystem::path> found;
    for (const auto& de : std::filesystem::directory_iterator(storageDir, ec))
    {
        if (ec)
        {
            break;
        }
        const auto& p = de.path();
        if (p.extension() != ".bin")
        {
            continue;
        }

        // Parse numeric stem as the entry id.
        const std::string stem = p.stem().string();
        uint64_t id = 0;
        auto [ptr, errc] =
            std::from_chars(stem.data(), stem.data() + stem.size(), id);
        if (errc != std::errc{} || ptr != stem.data() + stem.size())
        {
            removeUnloadable(p, "non-numeric CPER file name");
            continue;
        }
        found[id] = p;
    }

    for (auto& [id, path] : found)
    {
        // Read file back into memory.
        std::ifstream f(path, std::ios::binary);
        if (!f)
        {
            removeUnloadable(path, "cannot read file");
            continue;
        }
        std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());

        // Re-parse through the CPER class.
        properties prop;
        CPER cp(std::span<const unsigned char>(raw.data(), raw.size()));
        if (!cp.isValid())
        {
            removeUnloadable(path, "corrupt CPER file");
            continue;
        }
        cp.prepareToLog(prop);
        if (prop.empty())
        {
            removeUnloadable(path, "no sections in CPER file");
            continue;
        }

        filePaths[id] = path;
        entries[id] = std::make_shared<CperEntry>(server, id, prop[0],
                                                  cp.getJson(), path.string());
        if (id >= nextId)
        {
            nextId = id + 1;
        }
        lg2::debug("Loaded CPER entry {ID} from {PATH}", "ID", id, "PATH",
                   path.string());
    }

    // Evict only genuine excess; no new entry is pending, so don't reserve
    // a slot for one. Best-effort at startup: nothing else to fall back to
    // if it can't fully reconcile, so the return value isn't checked here.
    enforceCapacity(0);
}

bool Manager::enforceCapacity(size_t incomingBytes)
{
    // A slot only needs to be reserved if an entry is actually about to be
    // inserted; loadExisting() passes incomingBytes=0 purely to reconcile
    // against limits that may have tightened since the last boot.
    bool reservingSlot = incomingBytes > 0;
    while (!entries.empty() &&
          ((reservingSlot ? entries.size() >= maxEntries
                          : entries.size() > maxEntries) ||
           totalStorageBytes() + incomingBytes > maxTotalBytes))
    {
        if (!removeOldest())
        {
            lg2::error(
                "Eviction made no progress; aborting capacity enforcement");
            return false;
        }
    }
    return true;
}

bool Manager::removeOldest()
{
    if (entries.empty())
    {
        return false;
    }
    auto it = entries.begin(); // lowest id == oldest
    uint64_t id = it->first;

    auto fp = filePaths.find(id);
    auto path = (fp != filePaths.end()) ? fp->second : entryPath(id);

    std::error_code ec;
    std::filesystem::remove(path, ec);
    if (ec)
    {
        lg2::error("Failed to remove {PATH}: {ERR}; keeping entry in memory",
                   "PATH", path.string(), "ERR", ec.message());
        return false;
    }

    filePaths.erase(id);
    entries.erase(it);
    lg2::info("Removed CPER entry {ID} at {PATH} to make room for a new entry",
             "ID", id, "PATH", path.string());
    return true;
}

void Manager::removeUnloadable(const std::filesystem::path& path,
                           const std::string& reason)
{
    lg2::warning("Removing unrecoverable CPER file {PATH}: {REASON}", "PATH",
                path.string(), "REASON", reason);
    std::error_code ec;
    std::filesystem::remove(path, ec);
    if (ec)
    {
        lg2::error("Failed to remove unloadable file {PATH}: {ERR}", "PATH",
                   path.string(), "ERR", ec.message());
    }
}

std::filesystem::path Manager::entryPath(uint64_t id) const
{
    return storageDir / (std::format("{:010}", id) + ".bin");
}

size_t Manager::totalStorageBytes() const
{
    size_t total = 0;
    std::error_code ec;
    for (const auto& [id, _] : entries)
    {
        auto fp = filePaths.find(id);
        auto path = (fp != filePaths.end()) ? fp->second : entryPath(id);
        auto size = std::filesystem::file_size(path, ec);
        if (ec)
        {
            ec.clear();
            continue;
        }
        total += size;
    }
    return total;
}

} // namespace phosphor::cper
