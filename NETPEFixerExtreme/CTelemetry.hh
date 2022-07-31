#pragma once
#include "CBinary.hh"
#include "CDiscordNetwork.hh"
#include <iostream>

namespace CTelemetry
{

	/// <summary>
	///		Esse método calcula o tamanho do payload atual para ser enviado ao bucket do discord e compara com o tamanho máximo permitido para envio
	/// </summary>
	/// <param name="ctx">Contexto do binário</param>
	/// <returns>Retorna verdadeiro se o binário pode ser enviado ao bucket do discord, e se seu tamanho não excede o limite máximo</returns>
	auto isDiscordBucketStorageMaxAllowed( CBinary * ctx ) -> bool;

	/// <summary>
	///		Esse método prepara o payload local para enviar binários para o servidor do discord para analise manual e estudos
	/// </summary>
	/// <param name="ctx">Contexto do binário</param>
	/// <returns>Se a requisição foi aceita e o usuário concordou ou se ocorreu algum problema ao enviar a requisição</returns>
	auto executeOperationSubmitBinary(
		CBinary* ctx
	) -> bool;

};

