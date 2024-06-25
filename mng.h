#ifndef MNG_H
#define MNG_H

#define STATUS_OK          0x00
#define AUTH_ERROR         0x01
#define INVALID_VERSION    0x02
#define INVALID_COMMAND    0x03
#define INVALID_REQUEST    0x04
#define UNEXPECTED_ERROR   0x05
#define TRANSF_NOT_DEFINED 0x06

#define DATAGRAM_LENGTH 14
#define PASS_LENGTH     8

#define PROTOCOL_SIGN_1  0xFF
#define PROTOCOL_SIGN_2  0xFE
#define PROTOCOL_VERSION 0x00

#define i_PROT_SIGN_1 0
#define i_PROT_SIGN_2 1
#define i_VERSION     2
#define i_IDENTIF_1   3
#define i_IDENTIF_2   4
#define i_AUTH        5
#define i_COMMAND     13

#define i_STATUS     5
#define i_RES_OFFSET 6

#define MAX_COMMAND 0x06

#define COM_HISTORIC   0x00
#define COM_CONCURRENT 0x01
#define COM_BYTES      0x02
#define COM_MAILS      0x03
#define COM_TRANSFORM  0x04
#define COM_ENABLE     0x05
#define COM_DISABLE    0x06

#define RES_TRUE  0x00
#define RES_FALSE 0x01

#define ERROR_STATUS 1

#endif  // MNG_H
