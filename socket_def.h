/*
 *te31 project
 *socket_def.h
 *ver 0.1
 *author wxdao
 *of widesense
 */

#ifndef SOCKET_DEF_H
#define SOCKET_DEF_H

#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#define closesocket(x) close(x)
#else
#include <winsock2.h>
#endif

#define FASTADDR(a,x,y,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=inet_addr(y);\
  ((sockaddr_in*)&a)->sin_port=htons(z)

#define FASTADDR_ANY(a,x,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=INADDR_ANY;\
  ((sockaddr_in*)&a)->sin_port=htons(z)
#ifdef _WIN32
#define INITWSA  \
  WORD wVersionRequested;\
  WSADATA wsaData;\
  wVersionRequested=MAKEWORD(1, 1);\
  WSAStartup(wVersionRequested, &wsaData)
#else
#define INITWSA
#endif

#endif // SOCKET_DEF_H
