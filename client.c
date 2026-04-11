#include <stdio.h>

#include <curl/curl.h>
#include <gmp.h>
#include <cjson/cJSON.h>

#include "../../set1/Challenge2/xorHelper.c"

unsigned char salt_hex[32];

// Struct to store libcurl response
struct MemoryBlock {
    char *memory;
    size_t size;
};

// Callback to handle incoming data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryBlock *mem = (struct MemoryBlock *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0; // out of memory!

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void extract_salt(char *json_string) {
    cJSON *root = cJSON_Parse(json_string);
    if (!root) {
        printf("Error parsing JSON\n");
        return;
    }

    // Extracting the "salt"
    cJSON *salt_item = cJSON_GetObjectItemCaseSensitive(root, "salt");
    if (cJSON_IsString(salt_item) && (salt_item->valuestring != NULL)) {
        printf("Extracted Salt: %s\n", salt_item->valuestring);
        memcpy(salt_hex, salt_item->valuestring, 32);
    }
    cJSON_Delete(root);
}

int main(){
    // Client get_salt()
    CURL* curl_handle;
    CURLcode res;
    struct MemoryBlock chunk = {malloc(1), 0};

    curl_handle = curl_easy_init();

    if(curl_handle){
        curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/get_salt");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    }
    res = curl_easy_perform(curl_handle);
    long response_code = 0;
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
        if(response_code == 201){
            extract_salt(chunk.memory);
        }
    }
    curl_easy_cleanup(curl_handle);
    free(chunk.memory);
    
    // send I
    // Server returns SALT

    // Client register()
    // send I, v
    // Server returns OK

    // Client auth_first_step()
    // send I, A
    // Server returns B

    // Compute x, xH, u, uH, S and K

    // Compute HMAC_SHA256(K, salt)

    // Send HMAC to Server
    // Server returns 200 if okay else 401
    return 0;
}