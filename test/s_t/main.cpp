#include <iostream>
#include "sc.h"
#include "stdlib.h"
#include "string.h"

using namespace std;

#define prt(x) cout<<x<<endl;


int main(int argc,char* argv[])
{
  INITWSA;
  cout << "Hello World!" << endl;
//  long sck = socket(AF_INET,SOCK_STREAM,0);
//  int on = 1;
//  setsockopt(sck,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
//  sockaddr addr;
//  FASTADDR_ANY(addr,AF_INET,46424);
//  bind(sck,&addr,sizeof(addr));
  init_secure_memory(102400);
  long sck=start_tcp_server(0,46424);
  skey_map_t km;
  key_info ki;
  prt("A shared password:");
  string passwd;
  cin >> passwd;
  ki.key_data=(void*)(passwd.c_str());
  ki.key_size=passwd.length();
  km["test"]=ki;
  listen_wap(sck,128);
  prt("Waiting...");
  char dip[64]={0};
  long shit =accept_wap(sck,dip);
  prt("One wants in.");
  byte a;
  char b[64];
  char c[10];
  strcpy(c,"test");
  int err = setup_secure(shit,km,&a,b,0,c);
  if(err)
    {
      prt("Enemy confirmed.Run!");
      return 0;
    }
  prt("Friend confirmed.Secure link established.");
  char lkj[1024]={0};
  size_t shitfdhkjsa;
  byte jk;
  while(1)
    {
      int ret = recv_secure(shit,lkj,1024,&shitfdhkjsa,&jk);
      if(ret<0)
        {
          prt("Enemy confirmed.Run!");
          prt(ret);
          int jkl;
          cin >> jkl;
          return 0;
        }
      prt(lkj);
    }


  return 0;
}

