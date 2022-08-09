#include "CBinary.hh"


/// <summary>
///		Esse m�todo privado calcula o tamanho do arquivo no contexto, a quantidade de bytes, sendo ele um bin�rio ou plaintext
/// </summary>
auto CBinary::calculateFileSize( void ) -> void {
	this->fileSize = this->f.tellg( );
	this->f.seekg( 0, std::ios::end );
	this->fileSize = this->f.tellg( ) - this->fileSize;
	this->mp( 0x00 );
}

/// <summary>
///		Getter para obter o tamanho do arquivo
/// </summary>
/// <returns>retorna o tamanho do arquivo armazenado e calculado ao abrir um novo arquivo</returns>
auto CBinary::getFSz( ) -> std::int64_t {
	return this->fileSize;
}

/// <summary>
///		Obtem o path do arquivo carregado na classe cbinary
/// </summary>
/// <returns>Retorna um objeto std::string contendo o path</returns>
auto CBinary::getFilePath( ) -> std::basic_string< char, std::char_traits< char >, std::allocator< char > > {
	return *this->filePath;
}

/// <summary>
///		Construtor da classe Binary na qual vai preparar o contexto de trabalho e manipula��o do arquivo
/// </summary>
/// <param name="path">Path do arquivo para trabalhar</param>
/// <param name="mode">Modo de abertura</param>
CBinary::CBinary( std::basic_string< char > path, std::ios::openmode mode, bool isPlaintext ) {

	if ( !isPlaintext ) {

		std::basic_string< wchar_t, std::char_traits< wchar_t >, std::allocator< wchar_t > > tmp( std::filesystem::temp_directory_path( ) );//C:\Users\usu�rio\AppData\Local\Temp
		tmp.append( L"NETPEFIXERBINARYRUNTIME.tmp" );
		this->filePath = new std::basic_string< char, std::char_traits< char >, std::allocator< char > >( tmp.begin( ), tmp.end( ) );
		//Sempre true visto que o diret�rio de destino n�o requer permiss�es de administrador
		( BOOL )CopyFile( std::basic_string< wchar_t, std::char_traits< wchar_t >, std::allocator< wchar_t > >( path.begin( ), path.end( ) ).c_str( ), tmp.c_str( ), FALSE ); //https://docs.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-copyfile?redirectedfrom=MSDN
		this->f.open( *this->filePath, mode );
		this->calculateFileSize( );

	}
	else {
		std::basic_string< wchar_t, std::char_traits< wchar_t >, std::allocator< wchar_t > > localPathWin( std::filesystem::current_path( ) );
		this->filePath = new std::basic_string< char, std::char_traits< char >, std::allocator< char > >( localPathWin.begin( ), localPathWin.end( ) );
		this->filePath->append( path.begin( ), path.end( ) ); //Quando plaintext refere-se a arquivos locais de trabalho de configura��o ou tempor�rios no mesmo diret�rio de trabalho!
		this->f.open( *this->filePath, mode );
		this->calculateFileSize( );

	}

}

/// <summary>
///		Esse m�todo faz o parsing do stream utilizado, para um objeto nlohmann::json
/// </summary>
/// <returns>Retorna um objeto nlohmann::json completo</returns>
auto CBinary::parseToJson( void ) -> nlohmann::json {
	try {
		return nlohmann::json::parse( this->f );
	}
	catch ( nlohmann::json::exception &ex ) {
		std::operator<<( 
						std::cerr,
						"Ocorreu um erro e por seguran�a o programa sera encerrado, erro ao parsear um arquivo json -> "
			).operator<<( ex.what( ) )
			.operator<<( std::endl );
	}
}

/// <summary>
///		Esse m�todo � respons�vel por escrever um buffer com tamanho pr�-determinado no bin�rio
/// </summary>
/// <param name="buff">Buffer a ser escrito</param>
/// <param name="buffSz">Tamanho do buffer a ser escrito</param>
auto CBinary::w( void* buff, std::size_t buffSz ) -> void {
	this->f.write( reinterpret_cast< char* >(buff), buffSz );
}

/// <summary>
///		Esse m�todo � respons�vel por ler um buffer de um bin�rio com tamanho pr�-determinado
/// </summary>
/// <param name="buff">Buffer a ser lido do bin�rio</param>
/// <param name="buffSz">Tamanho do buffer a ser lido do bin�rio</param>
auto CBinary::r( void* buff, std::size_t buffSz ) -> void {
	this->f.read( reinterpret_cast< char* >(buff), buffSz );
}

/// <summary>
///		Esse m�todo � respons�vel por mover o ponteiro no bin�rio
/// </summary>
/// <param name="offset">offset do arquivo no qual deseja-se mover o ponteiro</param>
auto CBinary::mp( std::int64_t offset ) -> void {
	//De acordo com a ISO do C++ essa fun��o limpa a flag eofbit!
	this->f.seekg( offset, std::ios::beg );
}

/// <summary>
///		Esse m�todo � respons�vel por retornar o ponteiro atual do bin�rio seu offset
/// </summary>
/// <returns>offset atual do contexto do arquivo</returns>
auto CBinary::gp( ) -> std::streamoff {
	return this->f.tellg( );
}

/// <summary>
///		Esse m�todo converte um endere�o virtual(RVA) para um offset de arquivo v�lido
/// </summary>
/// <param name="relativeVirtualAddress">RVA de no m�ximo 4 bytes</param>
/// <param name="ctx">Contexto de se��o</param>
/// <returns>O offset do arquivo</returns>
auto CBinary::converterRelativeVirtualAddressToFileOffset( std::uint64_t superidolhash, std::uint64_t NumberOfSections, void* ctx ) -> int {

	auto* ctxs = reinterpret_cast< IMAGE_SECTION_HEADER* >( ctx );

	for ( int i = 0; i < NumberOfSections; i++ )
		if ( ctxs[ i ].VirtualAddress <= superidolhash && ctxs[ i ].VirtualAddress + ctxs[ i ].SizeOfRawData >= superidolhash )
			return ctxs[ i ].PointerToRawData 
				   + ( superidolhash - ctxs[ i ].VirtualAddress ); //Somat�ria da diferen�a entre o valor atual da superidolhash e o endere�o virtual da se��o
	
	return 0; //O algoritmo original microsoft e themida n�o usam uma corre��o de offset de acordo quando n�o possui um offset v�lido

}

/// <summary>
///		EXECUTAR CASO DE TESTE NA L�GICA !
/// </summary>
auto CBinary::reconstruirRelocacoesNet(int relativeVirtualAddress) -> byte* {

	byte* arraya = new byte[12];
	int valor = static_cast<int>(static_cast<long>(relativeVirtualAddress) & static_cast<long>(static_cast<unsigned long>(-4096)));
	CMemSafety::safeMemMove((void *)arraya, (void *)valor, 4);
	for (auto i = 0; i < 4; i++)
		std::printf("%X ", *(arraya + i));
	int valor2 = 12;

	return nullptr; // RETORNAR PONTEIRO DE RELOCA��ES
}

/// <summary>
///		Esse m�todo fecha o contexto aberto do bin�rio no qual est� se trabalhando
/// </summary>
CBinary::~CBinary( ) {
	this->f.close( );
	//PRECISO APAGAR O TEMPORARIO E COPIAR O BIN�RIO CORRIGIDO DE VOLTA!
}