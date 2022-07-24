#include "CTelemetry.hh"

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
	
	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "banner" ] ) );

	std::operator<<( std::cout, std::basic_string< char, std::char_traits< char >, std::allocator< char > >( j[ "agreement" ] ) );
	
	return true;
}