#pragma once
#include "CBinary.hh"
#include "CDiscordNetwork.hh"
#include <iostream>

namespace CTelemetry
{

	/// <summary>
	///		Esse m�todo calcula o tamanho do payload atual para ser enviado ao bucket do discord e compara com o tamanho m�ximo permitido para envio
	/// </summary>
	/// <param name="ctx">Contexto do bin�rio</param>
	/// <returns>Retorna verdadeiro se o bin�rio pode ser enviado ao bucket do discord, e se seu tamanho n�o excede o limite m�ximo</returns>
	auto isDiscordBucketStorageMaxAllowed( CBinary * ctx ) -> bool;

	/// <summary>
	///		Esse m�todo prepara o payload local para enviar bin�rios para o servidor do discord para analise manual e estudos
	/// </summary>
	/// <param name="ctx">Contexto do bin�rio</param>
	/// <returns>Se a requisi��o foi aceita e o usu�rio concordou ou se ocorreu algum problema ao enviar a requisi��o</returns>
	auto executeOperationSubmitBinary(
		CBinary* ctx
	) -> bool;

};

