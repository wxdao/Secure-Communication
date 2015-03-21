/*
 *te31 project
 *te31_types.h
 *ver 0.1
 *author wxdao
 *of widesense
 */

#ifndef TE31_TYPES_HPP
#define TE31_TYPES_HPP

typedef unsigned char byte;

//Defines of s
#define S_ERR 0b00000001

//Defines of size
#define INIT_PKG_SIZE 92
#define SER_REP_PKG_SIZE 36
#define COMM_HEADER_SIZE 33
#define COMM_FOOTER_SIZE 24

//Init pkg 92 bytes
struct init_pkg
{
  byte opt;
  byte ver;
  byte A[64];
  byte n_size;
  byte gx_size;
  byte hash[24];
}__attribute__((__packed__));

//Server response pkg 36 bytes
struct ser_rep_pkg
{
  byte opt;
  byte B[10];
  byte gy_size;
  byte hash[24];
}__attribute__((__packed__));

//Communication header 33 bytes
struct comm_header
{
  byte opt;
  long size;
  long id;
  byte hash[24];
}__attribute__((__packed__));

//Communication footer 24 bytes
struct comm_footer
{
  byte hash[24];
}__attribute__((__packed__));

#endif // TE31_TYPES_HPP
