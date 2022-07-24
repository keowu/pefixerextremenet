#pragma once
#include <iostream>


struct DiscordPeFixer {
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> localFilePath;
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> discordAPI;
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> discordAvatar;
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> discordName;
	std::basic_string<char, std::char_traits<char>, std::allocator<char>>* returnJson;
};

class CDiscordNetwork
{

private:
	const std::basic_string<char, std::char_traits<char>, std::allocator<char>> DISCORD_API_BASE ="https://discord.com/api/webhooks/";
	static size_t register_curl_callback(void* buffer, size_t size, size_t memb, void* param);

public:
	CDiscordNetwork(DiscordPeFixer * ctx);
	~CDiscordNetwork();
};

