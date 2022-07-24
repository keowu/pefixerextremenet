#define CURL_STATICLIB
#include "CDiscordNetwork.hh"

//Compilar com flag Usar MFC em uma Static Library

//info: Atenção a versão utilizada do CURL e arquitetura na qual deseja direcionar o Net Pe Fixer
#include "The3rd/curl_7.84.0/x32 release/include/curl/curl.h";

// DEFININDO MSVC COMPILER qual lib deverá ser carregada!
#ifdef _DEBUG
#pragma comment(lib, "The3rd/curl_7.84.0/x32 debug/lib/libcurl_a_debug.lib")
#else
#pragma comment(lib, "The3rd/curl_7.84.0/x32 release/lib/libcurl_a.lib")
#endif

//Dependências para curl no msvc
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")

//Uma boa prática indicar que estamos utilizando código C, no C++ de acordo com a ISO
//https://isocpp.org/wiki/faq/mixing-c-and-cpp
extern "C" {

    auto CDiscordNetwork::register_curl_callback(void* buffer, size_t size, size_t memb, void* param) -> size_t {


        return 0;
    }



    CDiscordNetwork::CDiscordNetwork(DiscordPeFixer* ctx) {

        auto* curl = curl_easy_init();

        if (curl) {

            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

            std::basic_string<char, std::char_traits<char>, std::allocator<char>> DISCORD_BUCKET_ROUTE(DISCORD_API_BASE);
            DISCORD_BUCKET_ROUTE.append(ctx->discordAPI);

            curl_easy_setopt(curl, CURLOPT_URL, DISCORD_BUCKET_ROUTE.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Cookie: __dcfduid=6aaa91b60adb11edb5de167abf853a04; __sdcfduid=6aaa91b60adb11edb5de167abf853a04a2c20d61c049e48671f8e1861efe050d95e2218b1b2672723c384dfa2b43cdfa");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            auto* mime = curl_mime_init(curl);
            auto* part = curl_mime_addpart(mime);

            curl_mime_name(part, "username");
            curl_mime_data(part, ctx->discordName.c_str(), CURL_ZERO_TERMINATED);
            part = curl_mime_addpart(mime);

            curl_mime_name(part, "avatar_url");
            curl_mime_data(part, ctx->discordAvatar.c_str(), CURL_ZERO_TERMINATED);
            part = curl_mime_addpart(mime);

            curl_mime_name(part, "content");
            curl_mime_data(part, "Opa Galera, um novo sample foi enviado, aqui esta ele, boa analise :)", CURL_ZERO_TERMINATED);
            part = curl_mime_addpart(mime);

            curl_mime_name(part, "file1");
            curl_mime_filedata(part, ctx->localFilePath.c_str());

            curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

            auto res = curl_easy_perform(curl);
            curl_mime_free(mime);

        }
        curl_easy_cleanup(curl);

    }


    CDiscordNetwork::~CDiscordNetwork() {




    }

};