#include <stdio.h>

#include <curl/curl.h>
#include <gmp.h>
#include <cjson/cJSON.h>
#include <openssl/sha.h>


#include "../../set1/Challenge2/xorHelper.c"

unsigned char salt_hex[33];
unsigned char password[17] = "YELLOW SUBMARINE";
int password_length = 16;

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

static size_t silence_callback(void *contents, size_t size, size_t nmemb, void* userp){
    return size*nmemb;
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
        printf("salt_hex: %s\n", salt_item->valuestring);
        memcpy(salt_hex, salt_item->valuestring, 32);
    }
    cJSON_Delete(root);
}

int main(){
    

    // --------------------STARTUP--------------------
    mpz_t g, k, N, a, v;
    mpz_inits(g, k, N, a, v, NULL);
    gmp_randstate_t state;

    mpz_set_ui(g, 2);
    mpz_set_ui(k, 3);
    const char* nist_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";

    mpz_set_str(N, nist_p, 16);
    gmp_printf("N: %Zd\n", N);
    gmp_printf("g: %Zd\n", g);
    gmp_printf("k: %Zd\n", k);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, 12345);

    mpz_set_ui(a, 0);
    while(mpz_cmp_ui(a, 0) == 0){
        mpz_urandomm(a,state,N);
    }


    // ------------------Client get_salt()------------------
    // send I
    // Server returns SALT
    CURL* curl_handle;
    CURLcode res;
    struct MemoryBlock getsalt_chunk = {malloc(32), 0};

    curl_handle = curl_easy_init();

    if(curl_handle){
        curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/get_salt");
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&getsalt_chunk);
    } else {
        printf("curl_handle failed\n");
        return 1;
    }
    res = curl_easy_perform(curl_handle);
    long response_code = 0;
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
        if(response_code == 201){
            printf("get_salt() successful\n");
            extract_salt(getsalt_chunk.memory);
        }
    } else {
        printf("curl request failed\n");
        return 1;
    }
    free(getsalt_chunk.memory);
    
    

    // ------------------Client register()------------------
    // send I, v
    // Server returns OK
    

    unsigned char* salt_bytes = malloc(32);
    int salt_bytes_length = 0;
    salt_bytes = hexStringToRawString(salt_hex, salt_bytes, &salt_bytes_length);

    unsigned char* salt_and_password_to_hash = malloc(salt_bytes_length+password_length);
    memcpy(salt_and_password_to_hash, salt_bytes, salt_bytes_length);
    memcpy(salt_and_password_to_hash+salt_bytes_length,password,password_length);
    unsigned char xH_bytes[32];
    SHA256(salt_and_password_to_hash,salt_bytes_length+password_length,xH_bytes);
    unsigned char xH_hex[65];
    for(int i=0;i<64;i++){
        sprintf(xH_hex + (i * 2), "%02x", xH_bytes);
    }
    mpz_t x;
    mpz_inits(x, NULL);
    mpz_set_str(x, xH_hex, 16);

    mpz_powm(v, g, x, N);
    char* v_hex = mpz_get_str(NULL, 16, v);
    printf("v_hex: %s\n", v_hex);
    
    curl_easy_reset(curl_handle);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "v", v_hex);
    char* json_body = cJSON_Print(root);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, json_body);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl_handle, CURLOPT_URL, "localhost:5000/register");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, silence_callback);

    res = curl_easy_perform(curl_handle);
    if(res == CURLE_OK){
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,&response_code);
        if(response_code == 200){
            printf("register() successful\n");
        } else {
            printf("register() unsuccessful\n");
            return 1;
        }
    } else {
        printf("curl request failed\n");
        return 1;
    }
    curl_slist_free_all(headers);
    free(json_body);
    cJSON_Delete(root);




    // Client auth_first_step()
    // send I, A
    // Server returns B

    // Compute x, xH, u, uH, S and K

    // Compute HMAC_SHA256(K, salt)

    // Send HMAC to Server
    // Server returns 200 if okay else 401
    return 0;
}