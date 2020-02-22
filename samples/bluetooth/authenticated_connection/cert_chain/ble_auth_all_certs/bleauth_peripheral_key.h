/**
 *  @file bleauth_peripheral_key.h
 *
 *  @brief Private ECC P-256 key for the Peripheral cert, PEM format.
 *
 */

#ifndef _BLEAUTH_PERIPHERAL_KEY_H_
#define _BLEAUTH_PERIPHERAL_KEY_H_

const unsigned char bleauth_peripheral_key_pem[] = {
        "-- -- -BEGIN EC PARAMETERS-----\n"
        "BggqhkjOPQMBBw==\n"
        "-----END EC PARAMETERS-----\n"
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEICHS/LCDwBIVgmK5qnKHn0yex4URecfT0VZci4JMlpRRoAoGCCqGSM49"
        "AwEHoUQDQgAE1Rqd8lRZdNzxBCYSbShsgzhyh6PRf9pffceJez0Brvmam2voN6WC"
        "LaAMFKaS1YkfVETnZ1jmsJaHJbbEJOBZGg==\n"
        "-----END EC PRIVATE KEY-----\n"
};

#endif  /* _BLEAUTH_PERIPHERAL_KEY_H_ */
