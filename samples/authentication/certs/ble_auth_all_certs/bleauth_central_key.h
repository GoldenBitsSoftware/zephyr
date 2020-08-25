/**
 *  @file bleauth_central_key.h
 *
 *  @brief Private ECC P-256 key for the Central cert, PEM format.
 *
 */

#ifndef _BLEAUTH_CENTRAL_KEY_H_
#define _BLEAUTH_CENTRAL_KEY_H_

const unsigned char bleauth_central_key_pem[] = {
        "-----BEGIN EC PARAMETERS-----\n"
        "BggqhkjOPQMBBw==\n"
        "-----END EC PARAMETERS-----\n"
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIAjM+7VvIdX3sfOmqgQFuI5RgRua8DwVnxWL+TU4ajkcoAoGCCqGSM49"
        "AwEHoUQDQgAEIF8Tn5onQfschTqHHSiyFV3Ud0qu5RItSBmSnJognx2twXU4g6q0"
        "LgG1yWaRrXZP06uqu0I7AMFBuWVUFcep6w==\n"
        "-----END EC PRIVATE KEY-----\n"
};


#endif  /* _BLEAUTH_CENTRAL_KEY_H_ */


