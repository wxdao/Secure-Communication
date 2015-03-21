/*
 *te31 project
 *te31.h
 *ver 0.1.1
 *author wxdao
 *of widesense
 */

#ifndef TE31_H
#define TE31_H

#include "te31_types.h"
#include "socket_def.h"

#include <stdlib.h>
#include <map>
#include <vector>
#include <string>

struct key_info
{
  void *key_data;
  size_t key_size;
};

typedef std::map<std::string,key_info> skey_map_t;

//Note:ATTENTION ON THE RETURNED VALUE!!!(Check te13.cpp to know what the returned exactly means)
extern "C" long setup_secure(long sck,std::map<std::string,key_info> skey_map,byte *cflags,char cdesc[10],byte sflags,char sdesc[10]); //Used by server.Check a socket whether is correctly init securty.Return 0 if good.
extern "C" long send_secure(long sck,const void *msg,size_t len,byte flags); //Send data in secure way.Return a number > 0 if good.
extern "C" void get_data_from_pool(void *buf); //If the last recv_secure fails,data will be tmply stored in a pool(Note:Only the last data will be stored.It can be replaced if another len fail happens).Get data from pool
extern "C" long recv_secure(long sck,void *msg,size_t len,size_t *real_len,byte *flags); //Recv data in secure way.Return number > 0 if good.If len offered is smaller than real_len,it will return a specific number(<0)(I forgot what that number is.Please see te31.cpp to get the truth)
extern "C" long setup_secure_link(const char *ip,long port,const char desc[64],const void *skey,size_t skey_size,byte flags,char server_desc[10]); //Used by client.Init secure link.A socket long will be returned if good.

//Following funtion(functions) is(are) just a wrapper of socket.
extern "C" void init_shity_wsa();//Stupid WSA init.Fuck microshit.
extern "C" void init_secure_memory(long size);//It can only be set for once.
extern "C" long start_tcp_server(const char* bind_ip,long port);//Start a tcp server binded as you want.If you want to bind INADDR_ANY to it,simply set bind_ip NULL.Return socket long if good.
extern "C" long select_wap(long *scks,long n,long wait_time,long *tscks,long *tn);//Famous select() function with some simplifying tweaks.wait_time is in seconds.n is the socket number in scks.Note:Windows does not support more tham 64 scks at a time.Return what should be returned using regular select().tscks will be filled with sockets to be read.tn is the number of tscks.
extern "C" long listen_wap(long sck,long n);//See regular listen() document.
extern "C" long accept_wap(long sck,char *client_ip);//See regular accept() document.client_ip will be filled with client's ip(set it NULL to skip).Return remote sck;

#endif // TE31_H
