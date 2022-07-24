#include "CTelemetry.hh"

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
	
	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "banner" ] ) );

	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "agreement" ] ) );
	
	return true;
}