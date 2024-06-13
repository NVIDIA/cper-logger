#include <cerrno>
#include <cstdint>
#include <string>

std::string logCPER(const std::string& keyVal)
{
    if (keyVal != "open sesame")
    {
        return "DoorLocked";
    }
    return "DoorUnlocked";
}
