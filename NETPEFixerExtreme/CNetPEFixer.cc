#include "CNetPEFixer.hh"

/// <summary>
///		Esse método corrige as funções e caracterísitcas básicas para o loader da IL
/// </summary>
/// <param name="ctx">Contexto do binário</param>
auto CNetPEFixer::fixNetPE( CBinary* ctx ) -> void {
	
	bool corrigirDiretorioMetadata = true, corrigirBSJB = true, corrigirNumerosDosRVAseTamanhos = true; // EM DESENVOLVIMENTO OBVIAMENTE MUITO MAIS OPÇÕES VÃO ESTAR DISPONÍVEIS

	std::operator<<( std::operator<<( std::cout, "Corrigindo arquivo PE Net -> " ), ctx->getFilePath( ) ).operator<<( std::endl );

	ctx->mp( 0x00 );

	auto* idh = reinterpret_cast< IMAGE_DOS_HEADER * >( CMemSafety::getMemory( sizeof(IMAGE_DOS_HEADER) ) );

	ctx->r( idh, sizeof(IMAGE_DOS_HEADER) );

	if ( idh->e_magic != CBinaryType::MZ_PE_FILE )
		return;

	ctx->mp( idh->e_lfanew );

	auto* inh = reinterpret_cast< IMAGE_NT_HEADERS * >( CMemSafety::getMemory(sizeof(IMAGE_NT_HEADERS)) );

	ctx->r( inh, sizeof(IMAGE_NT_HEADERS) );

	if ( inh->Signature != CBinaryType::NT_PE_FILE )
		return;

	ctx->mp( static_cast< long >( idh->e_lfanew ) + 4 + sizeof(IMAGE_FILE_HEADER) + static_cast<int>( inh->FileHeader.SizeOfOptionalHeader ) );

	auto* sections = reinterpret_cast< IMAGE_SECTION_HEADER* >(CMemSafety::getMemory( sizeof(IMAGE_SECTION_HEADER) * inh->FileHeader.NumberOfSections) );

	ctx->r( sections, sizeof(IMAGE_SECTION_HEADER) * inh->FileHeader.NumberOfSections );

	for ( int i = 0; i < inh->FileHeader.NumberOfSections; i++ )
		std::operator<<( std::cout, ( *(sections + i)).Name ).operator<<( std::endl );

	bool flag = true;

	/// <summary>
	///		É o MetaDataDirectory zero ? se sim deu ruim e precisa ser consertado
	/// </summary>
	/// <param name="ctx">Definir flag para falso e ir corrigir</param>
	if ( inh->OptionalHeader.DataDirectory[14].VirtualAddress < 0 )
		flag = false;
	else {
		//Por preguiça de criar um segundo parâmetro e pelo meu colega de equipe não ficar quieto eu cirei a super idolhash: superidolhash = inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections
		int num = CBinary::converterRelativeVirtualAddressToFileOffset( 
			inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections,
			sections
			);
		if ( num == 0 ) {
			flag = false;
		}
	}

	if ( corrigirDiretorioMetadata ) {

		if ( !flag ) {

			int num2 = 0;
			int num3 = CBinary::converterRelativeVirtualAddressToFileOffset( 8192 << 8 | inh->FileHeader.NumberOfSections, sections );
			if (num3 != 0) {

				std::operator<<( std::cout, "O RVA do diretório MetaData do PE.net é inválido, vou fazer uma busca personalizada." ).operator<<( std::endl );
			    
				//Vamos mapear todo arquivo em memória
				ctx->mp( 0x00 );
				auto* binaryBytesRaw = CMemSafety::getMemory( ctx->getFSz( ) );
				ctx->r( binaryBytesRaw, ctx->getFSz( ) ); // vamos ler todo o arquivo e armazenar uma cópia de seus bytes de maneira segura


				for ( int i = 0; i < 30; i++ ) {
	
					bool isPatternFound = false;

					if ( *(binaryBytesRaw + (num3 + i)) == 72 && *(binaryBytesRaw + (num3 + i + 1)) == 0 && *(binaryBytesRaw + (num3 + i + 2)) == 0 &&
						*(binaryBytesRaw + (num3 + i + 3)) == 0)
						isPatternFound = true;
					
					if ( !isPatternFound )
						if (*(binaryBytesRaw + (num3 + i + 4)) == 2 && *(binaryBytesRaw + (num3 + i + 5)) == 0 && (*(binaryBytesRaw + (num3 + i + 6)) == 0 ||
							*(binaryBytesRaw + (num3 + i + 6)) == 5) && *(binaryBytesRaw + (num3 + i + 7)) == 0)
							isPatternFound = true;

					if ( !isPatternFound )
						if (*(binaryBytesRaw + (num3 + i + 16)) <= 31 && *(binaryBytesRaw + (num3 + i + 17)) == 0 && (*(binaryBytesRaw + (num3 + i + 18)) == 0 ||
							*(binaryBytesRaw + (num3 + i + 18)) == 1) && *(binaryBytesRaw + (num3 + i + 19)) <= 0 && *(binaryBytesRaw + (num3 + i + 23)) == 6)
							isPatternFound = true;
					
					byte b = *(binaryBytesRaw + (num3 + i + 16));

					if ( isPatternFound ) {
						num2 = CBinaryType::NT_PE_NET_THEMIDA_RVA_FOR_METADATA_DIR + i;
						break;
					}
				}

				//Encerrando caso não seja possível encontrar o RVA diretório .NET Metadata
				if ( num2 == 0 ) {
					std::operator<<( std::cout, "Falha ao tentar encontrar o RVA para o diratório Metadata .NET" )
						.operator<<( "\nVou encerrar a execução!" );
					return;
				}

				CMemSafety::safeMemMove( reinterpret_cast<void *>(num2), reinterpret_cast<void *>(*(binaryBytesRaw + idh->e_lfanew + 232)), sizeof(num2) ); //Copiando o valor do novo RVA
				int fixedRVASizeParaMetadata = 72; // Por padrão o Windows assume que o diretório Metadata em binários .NET sempre vai ter o tamanho padrão de 72
				CMemSafety::safeMemMove( reinterpret_cast<void *>( fixedRVASizeParaMetadata ), reinterpret_cast<void*>( *(binaryBytesRaw + idh->e_lfanew + 232 + 4) ), sizeof(int) ); //Vamos gravar o novo valor no arquivo atual
				
				//Limpando toda região mapeada e gravando arquivo
				ctx->mp( 0x00 );
				ctx->w( binaryBytesRaw, ctx->getFSz() ); // Vamos gravar todo conteúdo do arquivo mapeado na memória
				CMemSafety::memFlush( binaryBytesRaw ); // limpar o buffer da memória

				//Corrigindo o contexto atual que estamos trabalhando nesse arquivo
				inh->OptionalHeader.DataDirectory[14].VirtualAddress = num2; // Corrigindo RVA já presente na struct em memória
				inh->OptionalHeader.DataDirectory[14].Size = fixedRVASizeParaMetadata; // Definindo o tamanho do RVA padrão
				std::operator<<( std::cout, "Consegui um novo valor para seu RVA do MetaDataDirectory, agora ele será de " )
					.operator<<( std::hex ).operator<<( num2 ).operator<<( std::endl );
				flag = true;
			}
		}

		//continuar aqui com a lógica caso o diretório metadata esteja correto e não foi destruído pelo themida ou vmprotect
		if ( !flag )//Se mesmo após todas as válidações um RVA estiver equivocado e sua flag é hora de encerrar a correção e solicitar que o usuário encontre ou determine um valor
			std::invoke( []( void ) {
				std::operator<<( std::cout, "RVA é inválido para continuar !" ).operator<<( std::endl );
				exit( -1 );
			} );
		else {

			bool isMetaDataBSJBFixed = true;
			ctx->mp( static_cast<long>( CBinary::converterRelativeVirtualAddressToFileOffset(
				inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections, sections
			) + 8 ) );

			std::int32_t num4 = 0;
			ctx->r( &num4, sizeof(std::int32_t) );//std::int32_t e int32_t é o mesmo, então não abra uma PR!

			if (num4 <= 0)
				isMetaDataBSJBFixed = false;
			else {
				int num5 = CBinary::converterRelativeVirtualAddressToFileOffset( num4 << 8 | inh->FileHeader.NumberOfSections, sections );
				if ( num5 == 0 )
					isMetaDataBSJBFixed = false;
				if ( isMetaDataBSJBFixed ) {
					ctx->mp( (long)num5 );
					std::int32_t num6 = 0;
					ctx->r( &num6, sizeof(std::int32_t) );
					if ( num6 != 1112167234 ) {
						isMetaDataBSJBFixed = false;
					}
				}
			}

			//Os metadados .NET apontados pelo cabeçalho CLR/CLI sempre começam com a assinatura BSJB!
			//Para quem quiser se aprofundar: https://www.codeproject.com/Articles/5841/Inside-the-NET-Application
			//								  http://www.moserware.com/2007/11/mz-bsjb-and-joys-of-magic-constants-in.html
			if ( corrigirBSJB ) {

				int valorPredizidoParaBSJB = 0;
				if ( !isMetaDataBSJBFixed ) {

					//Vamos mapear todo arquivo em memória
					ctx->mp( 0x00 );
					auto* binaryBytesRaw = CMemSafety::getMemory( ctx->getFSz( ) );
					ctx->r( binaryBytesRaw, ctx->getFSz( ) ); // vamos ler todo o arquivo e armazenar uma cópia de seus bytes de maneira segura

					for ( int j = 0; j < ctx->getFSz( ); j++ )
					{
						if ( *(binaryBytesRaw+ j) == 66 && *(binaryBytesRaw + j + 1) == 83 && *(binaryBytesRaw + j + 2) == 74 && *(binaryBytesRaw + j + 3) == 66 )
						{
							if ( valorPredizidoParaBSJB != 0 )
							{
								valorPredizidoParaBSJB = -1;
							}
							else
							{
								valorPredizidoParaBSJB = CBinary::converterRelativeVirtualAddressToFileOffset( j << 8 | inh->FileHeader.NumberOfSections, sections );
							}
						}
					}

					std::operator<<( std::cout, "Estou corrigindo o RVA do MetaData (BSJB) !" );

					if ( valorPredizidoParaBSJB <= 0 )
						std::invoke( []( void ) {
							std::operator<<( std::cout, "Ocorreu uma falha ao tentar determinar o valor correto para o RVA do metataData(BSJB) !" );
							exit( -1 );
						} );

					std::operator<<( std::cout, "A partir de agora a ferramenta assumiu para (BSJB) o seguinte valor: " ).operator<<( std::hex ).operator<<( valorPredizidoParaBSJB );


					//Vamos salvar no arquivo o novo valor do BSJB assumido pela ferramenta
					CMemSafety::safeMemMove( &valorPredizidoParaBSJB, &*(binaryBytesRaw + ( CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections, sections ) + 8) ), sizeof(valorPredizidoParaBSJB) );
					
					//calculando tamanho da seção metadata!
					int sizePredicted = 0;
					std::int64_t offsetParaMetadaSecao = CBinary::converterRelativeVirtualAddressToFileOffset( valorPredizidoParaBSJB << 8 | inh->FileHeader.NumberOfSections, sections );
					ctx->mp( offsetParaMetadaSecao );
					

					/*
						AQUI É POSSÍVEL TRATAR O METADATA HEADER PARA FUTURAS APLICAÇÕES OU IDEIAS FUTURAS
						ISSO AQUI É UMA ANOTAÇÃO PARA O EU DO FUTURO, CASO DESEJA IMPLEMENTAR ALGUMA FUNÇÃO ENVOLVENDO ISSO.
					*/
					auto* mh = new MetaDataHeader;

					ctx->r( &mh->sign, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 4 );
					ctx->r( &mh->MajorVersion, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 6 );
					ctx->r( &mh->MinorVersion, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 8 );
					ctx->r( &mh->m$reserved, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 12 );
					ctx->r( &mh->length, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 16 );
		
					// Lógica para leitura da string da versão do cabeçalho BSJB
					std::invoke([ &mh, &ctx ] ( void ) {
						mh->versionMagicString = reinterpret_cast< std::byte* >( CMemSafety::getMemory( mh->length * sizeof(std::byte) ) ); // Byte tem o tamanho 1 de qualquer forma, porem é uma boa prática manter!
						for ( auto i = 0; i < mh->length; i++ )
							ctx->r( &*( mh->versionMagicString + i ), sizeof(byte) );
					} );

					ctx->mp( offsetParaMetadaSecao + 16 + mh->length );
					ctx->r( &mh->flags, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 18 + mh->length );
					ctx->r( &mh->NumberSections, sizeof(std::int16_t) );


					//Calculando o tamanho do Metadata

					auto Metasections = new MetaDataHeaderSections[ mh->NumberSections ];

					for ( int i = 0; i < mh->NumberSections; i++ ) {

						Metasections[i].headerctx = ctx->gp( );

						ctx->r( &Metasections[i].offset, sizeof(std::int32_t) );

						ctx->r( &Metasections[i].size, sizeof(std::int32_t) );

						char tmpArr[32]{ 0 };

						int ii = 0, ix = 0;

						byte b = 0;

						do {
							ctx->r( &b, 1 );

							tmpArr[ ii++ ] = b;

							ix++;

						} while ( b != 0 );

						int quantidade = ( ii % 4 != 0 ) ? ( 4 - ii % 4 ) : 0; // Determinando a quantidade lida bytes obtida da MetaDataSection
						
						ctx->mp( ctx->gp( ) + quantidade );  // Devo mover a quantidade correta

						if ( static_cast< int >( mh->NumberSections - 1 ) == i ) 
							sizePredicted = Metasections[i].offset + Metasections[i].size; // calculando o novo tamanho para a MetaData
						

					}

					if ( sizePredicted == 0 ) 

						std::invoke( [ ] ( void ) {

							std::operator<<(
								std::cerr, "Não foi possível obter o tamanho calculado correto para a Metadata, você deve predizer um valor ou encontra manualmente, recomendo usar o IDA ou PE Bear!\n"
								);
							exit(-1);

						} );
					
					else {

						std::operator<<( std::cout, "Definido um novo tamanho para a Metadata, agora será de " )
							.operator<<( std::hex )
							.operator<<( sizePredicted )
							.operator<<( std::endl );

						//Gravando valor recalculado do tamanho de metadata
						CMemSafety::safeMemMove( &sizePredicted, &*( binaryBytesRaw + CBinary::converterRelativeVirtualAddressToFileOffset(inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections, sections ) + 8 + 4 ), sizeof( int ) );

						ctx->mp( CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections, sections ) + 8 + 4 );

						ctx->w( &sizePredicted, sizeof( int ) );

					}

					//Limpando toda região mapeada e gravando arquivo
					CMemSafety::memFlush( Metasections );
					ctx->mp( 0x00 );
					ctx->w( binaryBytesRaw, ctx->getFSz( ) ); // Vamos gravar todo conteúdo do arquivo mapeado na memória
					CMemSafety::memFlush( binaryBytesRaw ); // limpar o buffer da memória

					isMetaDataBSJBFixed = true;

				}

			}

			if ( !isMetaDataBSJBFixed )
				std::invoke( [ ]( void ) {
					std::operator<<( std::cout, "A ferramenta falhou ao tentar determinar o RVA para Metadata (BSJB).\n" )
									.operator<<( "Por favor descubra ou determine um novo valor !" )
									.operator<<( std::endl );
					exit( -1 );
				} );
			
			else {

				if ( corrigirNumerosDosRVAseTamanhos && inh->OptionalHeader.NumberOfRvaAndSizes != CBinaryType::NT_PE_NET_MINIMUM_RVA_SIZES ) {
					ctx->mp( static_cast< long >( idh->e_lfanew + 116 ) );
					int PE_NET_MINIMUM_RVA = 16;
					ctx->w( &PE_NET_MINIMUM_RVA, sizeof(int) );
					std::operator<<( std::cout, "O RVA tinha um problema, o tamanho dele não cumpria o requisito minimo de 16, agora eu escrevi nele 16 para que o loader deixe-o passar !" ).operator<<( std::endl );
				}
				//APLICAR AQUI AS LÓGICAS PARA AS PRÓXIMAS CORREÇÕES !

			}



		}
	}

	/// <summary>
	///		Clean up memoria utilizada
	/// </summary>
	CMemSafety::memFlush( idh );
	CMemSafety::memFlush( inh );
	CMemSafety::memFlush( sections );
}