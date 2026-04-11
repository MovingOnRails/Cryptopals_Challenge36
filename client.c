#include <stdio.h>

#include <curl/curl.h>
#include <gmp.h>

int main(){
    // Client get_salt()
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
}