#pragma once
#include <iostream>

/// <summary>
///		Struct para armazenar informações de transações com bucket do discord
/// </summary>
struct DiscordPeFixer {
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > localFilePath;
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > discordAPI;
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > discordAvatar;
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > discordName;
	std::basic_string< char, std::char_traits< char >, std::allocator< char > >* returnJson;
};

class CDiscordNetwork
{

private:
	/// <summary>
	///		API BASE DO DISCORD
	/// </summary>
	const std::basic_string< char, std::char_traits< char >, std::allocator< char > > DISCORD_API_BASE ="https://discord.com/api/webhooks/"; //https://discord.com/developers/docs/resources/webhook
	
	/// <summary>
	///		Este método será utilizado para registrar callbacks do CURL, dessa forma para tratar e fornecer informações para o usuário
	/// </summary>
	/// <param name="buffer">Buffer retornado pelo curl</param>
	/// <param name="size">Tamanho do buffer</param>
	/// <param name="memb">Tipo de dado</param>
	/// <param name="param">Referência do parâmetro que será reinterpretado para armazenar</param>
	/// <returns>tamanho do buffer armazenado em param</returns>
	static size_t register_curl_callback(
		
		void* buffer,
		size_t size,
		size_t memb,
		void* param 
	
	);

public:

	/// <summary>
	///		Construtor da classe CDiscordNetwork para trabalhar com a requisição
	/// </summary>
	/// <param name="ctx">Struct Discord CONTEXT</param>
	CDiscordNetwork(
	
		DiscordPeFixer * ctx
	
	);
	
	/// <summary>
	///		Destructor da classe CDiscordNetwork
	/// </summary>
	~CDiscordNetwork(
		void
	);
};

