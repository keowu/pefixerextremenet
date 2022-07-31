#include "CTelemetry.hh"


/// <summary>
///		Esse m�todo calcula o tamanho do payload atual para ser enviado ao bucket do discord e compara com o tamanho m�ximo permitido para envio
/// </summary>
/// <param name="ctx">Contexto do bin�rio</param>
/// <returns>Retorna verdadeiro se o bin�rio pode ser enviado ao bucket do discord, e se seu tamanho n�o excede o limite m�ximo</returns>
auto CTelemetry::isDiscordBucketStorageMaxAllowed( CBinary* ctx ) -> bool {

	return ( ctx->getFSz( ) / 0.000001 ) > 8; //Para determinar o tamanho dos bytes em Megabytes utiliza-se a formul� da divis�o por 1e+6(1 expoente -6) 10x-6
										   //Por padr�o o bucket do discord n�o armazena arquivos superior ao tamanho m�ximo de 8 MegaBytes
										   // https://discord.com/developers/docs/topics/rate-limits
}


/// <summary>
///		Esse m�todo prepara o payload local para enviar bin�rios para o servidor do discord para analise manual e estudos
/// </summary>
/// <param name="ctx">Contexto do bin�rio</param>
/// <returns>Se a requisi��o foi aceita e o usu�rio concordou ou se ocorreu algum problema ao enviar a requisi��o</returns>
auto CTelemetry::executeOperationSubmitBinary( CBinary* ctx ) -> bool {

	auto* configf = new CBinary( "\\netPE.conf", std::ios::in, true );

	auto j = configf->parseToJson( );

	if ( std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "isEnabledSendTelemetry" ] ).find( "false" ) != std::basic_string< char, std::char_traits< char >, std::allocator< char > >::npos )
		
		return false;
	
	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "banner" ] ) ).operator<<( std::endl );

	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "agreement" ] ) ).operator<<( std::endl );
	
	if ( CTelemetry::isDiscordBucketStorageMaxAllowed( ctx ) ) {

		std::operator<<( std::cerr, "[X] Desculpe, o arquivo no qual voc� gostaria de contribuir excede o tamanho m�ximo do nosso bucket, cancelando envio, obrigado :) " );
		
		return false;

	}

	auto discordNetContext = new DiscordPeFixer( );

	discordNetContext->discordName = j[ "discordUsername" ].get< std::basic_string< char, std::char_traits< char >, std::allocator< char > > >( );
	
	discordNetContext->discordAvatar = j[ "discordAvatar" ].get< std::basic_string< char, std::char_traits< char >, std::allocator< char > > >( );
	
	discordNetContext->discordAPI = j[ "storagebucketdiscordapikey" ].get< std::basic_string< char, std::char_traits< char >, std::allocator< char > > >( );
	
	discordNetContext->localFilePath = ctx->getFilePath( );

	auto* discordNet = new CDiscordNetwork( discordNetContext );

	discordNet->~CDiscordNetwork( );

	return true;
}