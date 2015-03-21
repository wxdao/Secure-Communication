#include <iostream>
#include "sc.h"
#include <stdlib.h>
#include <string.h>

using namespace std;

#define prt(x) cout<<x<<endl;

int main(int argc,char* argv[])
{
  INITWSA;
  cout << "Hello World!" << endl;
//  gcry_control (GCRYCTL_INIT_SECMEM, 102400, 0);
//  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  init_secure_memory(102400);
  char fh[64],k[10];
  strcpy(fh,"hei");
  prt("Where is your friend?(ip)");
  string ipa;
  cin >> ipa;
  prt("A shared password:");
  string passwd;
  cin>>passwd;
  long sck= setup_secure_link(ipa.c_str(),46424,"test",passwd.c_str(),passwd.length(),0,k);
  if(sck<=0)
    {
      prt("Failed to set up secure link.");
      return 0;
    }
  prt("Secure link established.");
  while(1)
    {
      prt("Say something:");
      string ha;
      cin>>ha;
      int rrr = send_secure(sck,ha.c_str(),ha.length()+1,0);
      if(rrr<=0)
        {
          prt("Secure link cloesd");
        }
    }

  return 0;
}

