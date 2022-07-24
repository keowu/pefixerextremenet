#include "CTelemetry.hh"


/// <summary>
///		Esse método calcula o tamanho do payload atual para ser enviado ao bucket do discord e compara com o tamanho máximo permitido para envio
/// </summary>
/// <param name="ctx">Contexto do binário</param>
/// <returns>Retorna verdadeiro se o binário pode ser enviado ao bucket do discord, e se seu tamanho não excede o limite máximo</returns>
auto CTelemetry::itsDiscordBucketStorageMaxAllowed( CBinary* ctx ) -> bool {

	return (ctx->getFSz() / 0.000001) > 8; //Para determinar o tamanho dos bytes em Megabytes utiliza-se a formulá da divisão por 1e+6(1 expoente -6) 10x-6
										   //Por padrão o bucket do discord não armazena arquivos superior ao tamanho máximo de 8 MegaBytes
}


/// <summary>
///		Esse método prepara o payload local para enviar binários para o servidor do discord para analise manual e estudos
/// </summary>
/// <param name="ctx">Contexto do binário</param>
/// <returns>Se a requisição foi aceita e o usuário concordou ou se ocorreu algum problema ao enviar a requisição</returns>
auto CTelemetry::executeOperationSubmitBinary( CBinary* ctx ) -> bool {

	auto* configf = new CBinary( "\\netPE.conf", std::ios::in, true );

	auto j = configf->parseToJson( );

	if ( std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "isEnabledSendTelemetry" ] ).find( "false" ) != std::basic_string< char, std::char_traits< char >, std::allocator< char > >::npos )
		
		return false;
	
	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "banner" ] ) ).operator<<( std::endl );

	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "agreement" ] ) ).operator<<( std::endl );
	
	if (CTelemetry::itsDiscordBucketStorageMaxAllowed(ctx)) {

		std::operator<<( std::cerr, "[X] Desculpe, o arquivo no qual você gostaria de contribuir excede o tamanho máximo do nosso bucket, cancelando envio, obrigado :) " );
		
		return false;

	}

	auto discordNetContext = new DiscordPeFixer();

	discordNetContext->discordName = j["discordUsername"].get<std::basic_string< char, std::char_traits< char >, std::allocator< char > >>();
	discordNetContext->discordAvatar = j["discordAvatar"].get<std::basic_string< char, std::char_traits< char >, std::allocator< char > >>();
	discordNetContext->discordAPI = j["storagebucketdiscordapikey"].get<std::basic_string< char, std::char_traits< char >, std::allocator< char > >>();
	discordNetContext->localFilePath = ctx->getFilePath();

	auto* discordNet = new CDiscordNetwork(discordNetContext);

	discordNet->~CDiscordNetwork();

	return true;
}