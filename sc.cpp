/* 
 *sc project
 *sc.cpp
 *ver 0.1.20
 *author wxdao
 */

#include "sc.h"
#include "socket_def.h"

#include <gcrypt.h>

using namespace std;

map < long, key_info > key_map;
map < long, long >id_map;
map < long, vector < long >>id_used;

void init_shity_wsa()
{
  INITWSA;					// How stupid it is!
}

void init_secure_memory(long size)
{
  gcry_control(GCRYCTL_INIT_SECMEM, size, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

long start_tcp_server(const char *bind_ip, long port)
{
  long sck = socket(AF_INET, SOCK_STREAM, 0);
  unsigned int opt = 1;
  unsigned int len = sizeof(opt);
  int err = setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, len);
  if (err)
    {
      return err;
    }
  sockaddr addr;
  if (bind_ip)
    {
      FASTADDR(addr, AF_INET, bind_ip, port);
    }
  else
    {
      FASTADDR_ANY(addr, AF_INET, port);
    }
  if(bind(sck,&addr,sizeof(addr)))
    return -2;
  return sck;
}

long listen_wap(long sck,long n)
{
  return listen(sck,n);
}

long accept_wap(long sck,char *client_ip)
{
  sockaddr addr;
  int sz = sizeof(addr);
  long rsck=accept(sck,&addr,&sz);
  if(client_ip!=NULL)
    {
      strcpy(client_ip,inet_ntoa(((sockaddr_in*)&addr)->sin_addr));
    }
  return rsck;
}

long select_wap(long *scks,long n,long wait_time,long *tscks,long *tn)
{
  fd_set fds;
  struct timeval tv= {wait_time,0};
  FD_ZERO(&fds);
  long max=0;
  for(long i = 0;i<n;++i)
    {
      if(scks[i]>max)
        max=scks[i];
      FD_SET(scks[i],&fds);
    }
  int ret = select(max+1,&fds,0,0,&tv);
  *tn=0;
  for(long i = 0;i<n;++i)
    {
      if(FD_ISSET(scks[i],&fds))
        {
          tscks[(*tn)++]=scks[i];
        }
    }
  return ret;
}

size_t crypt_bound(size_t sz)
{
  size_t r = (int)(sz / 16) * 16;
  return r < sz ? r + 16 + 4 : r + 4;
}

char *itoa(int value, char *str, int radix)
{
  static char dig[] = "0123456789" "abcdefghijklmnopqrstuvwxyz";
  int n = 0, neg = 0;
  unsigned int v;
  char *p, *q;
  char c;
  if (radix == 10 && value < 0)
    {
      value = -value;
      neg = 1;
    }
  v = value;
  do
    {
      str[n++] = dig[v % radix];
      v /= radix;
    }
  while (v);
  if (neg)
    str[n++] = '-';
  str[n] = '\0';
  for (p = str, q = p + n / 2; p != q; ++p, --q)
    c = *p, *p = *q, *q = c;
  return str;
}

void generate_de_numbers(gcry_mpi_t & rn)
{
  gcry_mpi_t n2 = gcry_mpi_set_ui(NULL, 2);
  gcry_mpi_t n1 = gcry_mpi_set_ui(NULL, 1);
  bool out = true;
  gcry_mpi_t n, g, p;
  p = gcry_mpi_new(0);
  g = gcry_mpi_new(0);
  gcry_mpi_t w = gcry_mpi_new(0);
  while (out)
    {

      gcry_prime_generate(&n, 256, 0, 0, 0, 0, GCRY_STRONG_RANDOM, 0);
      // gcry_mpi_dump(n);
      gcry_mpi_lshift(p, n, 1);
      // gcry_mpi_mul_ui(p, n, 2);
      gcry_mpi_add_ui(p, p, 1);
      if (gcry_prime_check(p, 0) == 0)
        {
          // gcry_mpi_randomize(g,1,GCRY_WEAK_RANDOM);
          gcry_mpi_set_ui(g, 5);
          gcry_mpi_powm(w, g, n2, p);
          if (gcry_mpi_cmp(w, n1))
            {
              gcry_mpi_powm(w, g, n, p);
              if (gcry_mpi_cmp(w, n1))
                {
                  out = false;
                  rn = gcry_mpi_copy(p);
                  gcry_mpi_release(p);
                  gcry_mpi_release(g);
                  gcry_mpi_release(n);
                  gcry_mpi_release(w);
                  gcry_mpi_release(n1);
                  gcry_mpi_release(n2);
                  break;
                }
            }
          gcry_mpi_release(n);
        }
    }
}

void close_secure(long sck)
{
  closesocket(sck);
  gcry_free(key_map[sck].key_data);
  key_map.erase(sck);
  id_map.erase(sck);
  id_used.erase(sck);
}

int encrypt_aes(byte * out, size_t os, byte * in, size_t is, const char *key,
                long key_len)
{
  gcry_cipher_hd_t ghd;
  char i[16] = { 0 };
  strcpy(i, "te31");
  gcry_cipher_open(&ghd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, 0);
  gcry_cipher_setkey(ghd, key, key_len);
  gcry_cipher_setiv(ghd, i, 16);
  if (os != crypt_bound(is))
    return -1;
  int err = gcry_cipher_encrypt(ghd, out, os - sizeof(size_t), in, is);
  size_t padding = is;
  memmove(out + os - sizeof(size_t), &padding, sizeof(size_t));
  gcry_cipher_close(ghd);
  return err;
}

int decrypt_aes(byte * out, size_t * os, byte * in, size_t is, const char *key,
                long key_len)
{
  gcry_cipher_hd_t ghd;
  char i[16] = { 0 };
  strcpy(i, "te31");
  gcry_cipher_open(&ghd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB, 0);
  gcry_cipher_setkey(ghd, key, key_len);
  gcry_cipher_setiv(ghd, i, 16);
  if (*os < is)
    return -1;
  int err = gcry_cipher_decrypt(ghd, out, *os - sizeof(size_t), in,
                                is - sizeof(size_t));
  memmove(os, in + is - sizeof(size_t), sizeof(size_t));
  gcry_cipher_close(ghd);
  return err;
}

std::string formatbyte(byte * b, const size_t & sz, const int base)
{
  string hexstr = "";
  char tmp[3];
  for (unsigned int i = 0; i < sz; i++)
    {
      memset(tmp, 0, 3);
      itoa(*(b + i), tmp, base);
      if (strlen(tmp) == 1)
        {
          *(tmp + 1) = *tmp;
          *tmp = '0';
        }
      hexstr += tmp;
    }
  return hexstr;
}

long setup_secure(long sck, map < string, key_info > skey_map, byte * cflags,
                  char cdesc[10], byte sflags, char sdesc[10])
{
  init_pkg ipkg;
  memset(&ipkg, 0, INIT_PKG_SIZE);
  timeval tv = { 10, 0 };
  fd_set fdread;
  FD_ZERO(&fdread);
  FD_SET(sck, &fdread);
  int ret = select(sck + 1, &fdread, 0, 0, &tv);
  if (ret > 0)
    {
      if (FD_ISSET(sck, &fdread))
        {
          int err = recv(sck, (char *)&ipkg, INIT_PKG_SIZE, 0);
          if (err <= 0)
            {
              closesocket(sck);
              return -1;
            }
          byte *n_data = (byte *) malloc(ipkg.n_size + ipkg.gx_size);
          byte *gx_data = n_data + ipkg.n_size;
          memset(n_data, 0, ipkg.n_size + ipkg.gx_size);
          err = recv(sck, (char *)n_data, ipkg.n_size + ipkg.gx_size, 0);
          if (err <= 0)
            {
              closesocket(sck);
              return -2;
            }
          // Check hash
          string A_str = (char *)(ipkg.A);
          char rhash[24] = { 0 };
          gcry_md_hd_t mh;
          gcry_md_open(&mh, GCRY_MD_TIGER2,
                       GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
          gcry_md_setkey(mh, skey_map[A_str].key_data,
                         skey_map[A_str].key_size);
          gcry_md_write(mh, (const void *)&(ipkg.opt), sizeof(ipkg.opt));	// i
          gcry_md_write(mh, gx_data, ipkg.gx_size);	// gx
          gcry_md_write(mh, n_data, ipkg.n_size);	// n
          gcry_md_write(mh, ipkg.A, sizeof(ipkg.A));	// A
          memcpy(rhash, gcry_md_read(mh, GCRY_MD_TIGER2), sizeof(ipkg.hash));
          gcry_md_close(mh);
          if (memcmp(rhash, ipkg.hash, 24) != 0)
            {
              closesocket(sck);
              free(n_data);
              return -3;
            }
          *cflags = ipkg.opt;
          memmove(cdesc, ipkg.A, 64);
          // Write server response pkg
          ser_rep_pkg spkg;
          memmove(spkg.B, sdesc, 10);
          spkg.opt = sflags;
          // Set gy
          gcry_mpi_t n, rb;
          gcry_mpi_scan(&n, GCRYMPI_FMT_USG, n_data, ipkg.n_size, 0);
          gcry_mpi_t gy = gcry_mpi_new(0);
          rb = gcry_mpi_new(0);
          gcry_mpi_randomize(rb, 256, GCRY_STRONG_RANDOM);
          gcry_mpi_powm(gy, gcry_mpi_set_ui(0, 5), rb, n);
          byte *gy_data;
          size_t gy_data_size;
          gcry_mpi_aprint(GCRYMPI_FMT_USG, &gy_data, &gy_data_size, gy);
          spkg.gy_size = gy_data_size;
          // Hash
          gcry_md_hd_t mh_s;
          gcry_md_open(&mh_s, GCRY_MD_TIGER2,
                       GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
          gcry_md_setkey(mh_s, skey_map[A_str].key_data,
                         skey_map[A_str].key_size);
          gcry_md_write(mh_s, (const void *)&(ipkg.opt), sizeof(ipkg.opt));	// i
          gcry_md_write(mh_s, (const void *)&(spkg.opt), sizeof(spkg.opt));	// s
          gcry_md_write(mh_s, gx_data, ipkg.gx_size);	// gx
          gcry_md_write(mh_s, gy_data, spkg.gy_size);	// gy
          gcry_md_write(mh_s, ipkg.A, sizeof(ipkg.A));	// A
          gcry_md_write(mh_s, spkg.B, sizeof(spkg.B));	// B
          memcpy(spkg.hash, gcry_md_read(mh_s, GCRY_MD_TIGER2),
                 sizeof(spkg.hash));
          // Send
          char *tosend = (char *)malloc(SER_REP_PKG_SIZE + gy_data_size);
          memmove((char *)tosend, &spkg, SER_REP_PKG_SIZE);
          memmove((char *)tosend + SER_REP_PKG_SIZE, gy_data,
                  gy_data_size);
          send(sck, tosend, SER_REP_PKG_SIZE + gy_data_size, 0);
          // Obtain session key
          gcry_mpi_t gx, ks = gcry_mpi_new(0);
          gcry_mpi_scan(&gx, GCRYMPI_FMT_USG, gx_data, ipkg.gx_size, NULL);
          gcry_mpi_powm(ks, gx, rb, n);
          void *ks_data = gcry_malloc_secure(33);
          size_t ks_size;
          gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)ks_data, 33,
                         &ks_size, ks);
          key_info ki;
          ki.key_data = ks_data;
          ki.key_size = ks_size;
          key_map[sck] = ki;
          id_map[sck] = 0;
          vector < long >used_id;
          id_used[sck] = used_id;
          // Clean
          free(n_data);
          gcry_mpi_release(gx);
          gcry_mpi_release(gy);
          gcry_mpi_release(ks);
          gcry_mpi_release(rb);
          return 0;
        }
    }
  closesocket(sck);
  return -4 - ret;
}

long send_secure(long sck, const void *msg, size_t len, byte flags)
{
  // Simply set a comm header
  comm_header *cheader =
      (comm_header *) malloc(COMM_HEADER_SIZE + 24 + crypt_bound(len));
  cheader->opt = flags;
  cheader->id = ++id_map[sck];
  cheader->size = crypt_bound(len);
  // Encrypt msg
  void *ecpted = (char *)cheader + COMM_HEADER_SIZE;
  encrypt_aes((byte *) ecpted, cheader->size, (byte *) msg, len,
              (char *)(key_map[sck].key_data),
              key_map[sck].key_size < 32 ? 16 : 32);
  // header hash
  gcry_md_hd_t mh_h;
  gcry_md_open(&mh_h, GCRY_MD_TIGER2,
               GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh_h, key_map[sck].key_data,
                 key_map[sck].key_size < 32 ? 16 : 32);
  gcry_md_write(mh_h, &(cheader->opt), sizeof(cheader->opt));	// d
  gcry_md_write(mh_h, &(cheader->size), sizeof(cheader->size));	// size
  gcry_md_write(mh_h, &(cheader->id), sizeof(cheader->id));	// id
  memcpy(cheader->hash, gcry_md_read(mh_h, GCRY_MD_TIGER2),
         sizeof(cheader->hash));
  gcry_md_close(mh_h);
  // Footer
  comm_footer *cfooter =
      (comm_footer *) ((char *)cheader + COMM_HEADER_SIZE +
                       crypt_bound(len));
  gcry_md_hd_t mh;
  gcry_md_open(&mh, GCRY_MD_TIGER2, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh, key_map[sck].key_data,
                 key_map[sck].key_size < 32 ? 16 : 32);
  gcry_md_write(mh, cheader, COMM_HEADER_SIZE);	// header
  gcry_md_write(mh, ecpted, crypt_bound(len));	// content
  memcpy(cfooter, gcry_md_read(mh, GCRY_MD_TIGER2), sizeof(cheader->hash));
  gcry_md_close(mh);
  long slen = send(sck, (const char *)cheader,
                   COMM_HEADER_SIZE + 24 + crypt_bound(len), 0);
  if (slen <= 0)
    {
      closesocket(sck);
      gcry_free(key_map[sck].key_data);
      key_map.erase(sck);
      id_map.erase(sck);
      id_used.erase(sck);
    }
  free(cheader);
  return slen;
}

void *fuckyou_pool = NULL;
size_t fuckyou_pool_size = 0;

void push_fuckyou_pool(void *shit, size_t len)
{
  if (fuckyou_pool == NULL)
    {
      fuckyou_pool_size = len;
      fuckyou_pool = malloc(len);
      memmove(fuckyou_pool, shit, len);
    }
  else
    {
      memset(fuckyou_pool, 0, fuckyou_pool_size);
      free(fuckyou_pool);
      fuckyou_pool_size = len;
      fuckyou_pool = malloc(len);
      memmove(fuckyou_pool, shit, len);
    }
}

void get_data_from_pool(void *buf)
{
  memmove(buf, fuckyou_pool, fuckyou_pool_size);
  memset(fuckyou_pool, 0, fuckyou_pool_size);
  free(fuckyou_pool);
  fuckyou_pool = NULL;
}

bool check_id(long sck, long id)
{
  for (long i:id_used[sck])
    {
      if (id == i)
        return false;
    }
  return true;
}

long recv_secure(long sck, void *msg, size_t len, size_t * real_len,
                 byte * flags)
{
  comm_header cheader;
  int err = recv(sck, (char *)&cheader, COMM_HEADER_SIZE, 0);
  if (err <= 0)
    {
      gcry_free(key_map[sck].key_data);
      key_map.erase(sck);
      id_map.erase(sck);
      id_used.erase(sck);
      close_secure(sck);
      return -1;
    }
  // Check hash
  char rhash[24] = { 0 };
  gcry_md_hd_t mh_h;
  gcry_md_open(&mh_h, GCRY_MD_TIGER2,
               GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh_h, key_map[sck].key_data,
                 key_map[sck].key_size < 32 ? 16 : 32);
  gcry_md_write(mh_h, &(cheader.opt), sizeof(cheader.opt));	// d
  gcry_md_write(mh_h, &(cheader.size), sizeof(cheader.size));	// size
  gcry_md_write(mh_h, &(cheader.id), sizeof(cheader.id));	// id
  memcpy(rhash, gcry_md_read(mh_h, GCRY_MD_TIGER2), sizeof(rhash));
  gcry_md_close(mh_h);
  if (memcmp(cheader.hash, rhash, 24) != 0)
    {
      gcry_free(key_map[sck].key_data);
      key_map.erase(sck);
      id_map.erase(sck);
      id_used.erase(sck);
      closesocket(sck);
      return -2;
    }
  flags == NULL ? 0 : memmove(flags, &(cheader.opt), sizeof(cheader.opt));
  bool idfail = false;
  if (!check_id(sck, cheader.id))
    {
      idfail = true;
    }
  if (!idfail)
    id_used[sck].push_back(cheader.id);
  // Obtain content
  char *content = (char *)malloc(cheader.size);
  recv(sck, content, cheader.size, 0);
  char rhash_footer[24] = { 0 }, hash_footer[24] =
  {
    0};
  recv(sck, hash_footer, 24, 0);
  // Check footer hash
  if (idfail)
    {
      free(content);
      return -3;
    }
  gcry_md_hd_t mh;
  gcry_md_open(&mh, GCRY_MD_TIGER2, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh, key_map[sck].key_data,
                 key_map[sck].key_size < 32 ? 16 : 32);
  gcry_md_write(mh, &cheader, COMM_HEADER_SIZE);	// header
  gcry_md_write(mh, content, cheader.size);	// content
  memcpy(rhash_footer, gcry_md_read(mh, GCRY_MD_TIGER2),
         sizeof(rhash_footer));
  gcry_md_close(mh);
  if (memcmp(hash_footer, rhash_footer, 24) != 0)
    {
      gcry_free(key_map[sck].key_data);
      key_map.erase(sck);
      id_map.erase(sck);
      id_used.erase(sck);
      closesocket(sck);
      return -4;
    }
  // Decrypt
  size_t clen = cheader.size;
  char *decpted = (char *)malloc(cheader.size);
  decrypt_aes((byte *) decpted, &clen, (byte *) content, cheader.size,
              (char *)(key_map[sck].key_data),
              key_map[sck].key_size < 32 ? 16 : 32);
  if (len >= clen)
    {
      memmove(msg, decpted, clen);
      *real_len = clen;
      free(decpted);
      free(content);
      return 0;
    }
  else
    {
      memset(msg, 0, len);
      push_fuckyou_pool(decpted, clen);
      *real_len = clen;
      free(decpted);
      free(content);
      return -5;
    }
}

long setup_secure_link(const char *ip, long port, const char desc[64],
const void *skey, size_t skey_size, byte flags,
char server_desc[10])
{
  // generate a de number pair
  gcry_mpi_t ra;
  gcry_mpi_t n;
  generate_de_numbers(n);
  byte *n_data;
  size_t n_data_size;
  gcry_mpi_aprint(GCRYMPI_FMT_USG, &n_data, &n_data_size, n);
  // generate gx
  gcry_mpi_t gx = gcry_mpi_new(0);
  ra = gcry_mpi_new(0);
  gcry_mpi_randomize(ra, 256, GCRY_STRONG_RANDOM);
  gcry_mpi_powm(gx, gcry_mpi_set_ui(0, 5), ra, n);
  byte *gx_data;
  size_t gx_data_size;
  gcry_mpi_aprint(GCRYMPI_FMT_USG, &gx_data, &gx_data_size, gx);
  // Write init pkg
  init_pkg *ipkg =
      (init_pkg *) malloc(INIT_PKG_SIZE + gx_data_size + n_data_size);
  memset(ipkg, 0, INIT_PKG_SIZE + gx_data_size + n_data_size);
  ipkg->opt = flags;
  ipkg->ver = 2;
  strcpy((char *)(ipkg->A), desc);
  ipkg->gx_size = gx_data_size;
  ipkg->n_size = n_data_size;
  // Hash
  gcry_md_hd_t mh;
  gcry_md_open(&mh, GCRY_MD_TIGER2, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh, skey, skey_size);
  gcry_md_write(mh, (const void *)&(ipkg->opt), sizeof(ipkg->opt));	// i
  gcry_md_write(mh, gx_data, gx_data_size);	// gx
  gcry_md_write(mh, n_data, n_data_size);	// n
  gcry_md_write(mh, ipkg->A, sizeof(ipkg->A));	// A
  memset(ipkg->hash, 0, 24);
  memcpy(ipkg->hash, gcry_md_read(mh, GCRY_MD_TIGER2), sizeof(ipkg->hash));
  gcry_md_close(mh);
  memmove((char *)ipkg + INIT_PKG_SIZE, n_data, n_data_size);
  memmove((char *)ipkg + INIT_PKG_SIZE + n_data_size, gx_data,
          gx_data_size);
  long ipkg_size = INIT_PKG_SIZE + n_data_size + gx_data_size;
  // Ours done,then check server's
  long sck = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr to_server_addr;
  FASTADDR(to_server_addr, AF_INET, ip, port);
  int err = connect(sck, &to_server_addr, sizeof(to_server_addr));
  if (err)
    return -1;
  send(sck, (const char *)ipkg, ipkg_size, 0);
  char buf[1024];
  fd_set fdread;
  FD_ZERO(&fdread);
  FD_SET(sck, &fdread);
  timeval tv = { 10, 0 };
  int ret = select(sck + 1, &fdread, 0, 0, &tv);
  if (ret > 0)
    {
      int recv_len = recv(sck, buf, 1024, 0);
      if (recv_len <= (int)SER_REP_PKG_SIZE)
        {
          closesocket(sck);
          free(ipkg);
          free(gx_data);
          gcry_mpi_release(gx);
          gcry_mpi_release(ra);
          gcry_mpi_release(n);
          return -2;
        }
    }
  else
    {
      closesocket(sck);
      free(ipkg);
      free(gx_data);
      gcry_mpi_release(gx);
      gcry_mpi_release(ra);
      gcry_mpi_release(n);
      return -5 - ret;
    }
  ser_rep_pkg *spkg = (ser_rep_pkg *) buf;
  server_desc == NULL ? 0 : strcpy(server_desc, (char *)(spkg->B));
  byte *gy_data = (byte *) malloc(spkg->gy_size);
  memmove((char *)gy_data, (char *)spkg + SER_REP_PKG_SIZE,
          spkg->gy_size);
  // Check hash
  char rhash[24] = { 0 };
  gcry_md_hd_t mh_s;
  gcry_md_open(&mh_s, GCRY_MD_TIGER2,
               GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
  gcry_md_setkey(mh_s, skey, skey_size);
  gcry_md_write(mh_s, (const void *)&(ipkg->opt), sizeof(ipkg->opt));	// i
  gcry_md_write(mh_s, (const void *)&(spkg->opt), sizeof(spkg->opt));	// s
  gcry_md_write(mh_s, gx_data, gx_data_size);	// gx
  gcry_md_write(mh_s, gy_data, spkg->gy_size);	// gy
  gcry_md_write(mh_s, ipkg->A, sizeof(ipkg->A));	// A
  gcry_md_write(mh_s, spkg->B, sizeof(spkg->B));	// B
  memcpy(rhash, gcry_md_read(mh_s, GCRY_MD_TIGER2), sizeof(rhash));
  gcry_md_close(mh_s);
  if (memcmp(rhash, spkg->hash, sizeof(spkg->hash)) != 0)
    {
      closesocket(sck);
      free(ipkg);
      free(gx_data);
      free(gy_data);
      gcry_mpi_release(gx);
      gcry_mpi_release(ra);
      gcry_mpi_release(n);
      return -3;
    }
  if (spkg->opt & S_ERR)
    {
      closesocket(sck);
      free(ipkg);
      free(gx_data);
      free(gy_data);
      gcry_mpi_release(gx);
      gcry_mpi_release(ra);
      gcry_mpi_release(n);
      return -4;
    }
  // Obtain the session key
  gcry_mpi_t gy, ks = gcry_mpi_new(0);
  gcry_mpi_scan(&gy, GCRYMPI_FMT_USG, gy_data, spkg->gy_size, NULL);
  gcry_mpi_powm(ks, gy, ra, n);
  void *ks_data = gcry_malloc_secure(33);
  size_t ks_size;
  gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)ks_data, 33, &ks_size,
                 ks);
  key_info ki;
  ki.key_data = ks_data;
  ki.key_size = ks_size;
  key_map[sck] = ki;
  // Clean
  free(ipkg);
  free(gx_data);
  free(gy_data);
  gcry_mpi_release(gx);
  gcry_mpi_release(gy);
  gcry_mpi_release(ra);
  gcry_mpi_release(n);
  gcry_mpi_release(ks);
  id_map[sck] = 0;
  vector < long >used_id;
  id_used[sck] = used_id;
  // //Test //Make users to do this
  // if(!send_secure(sck,"HELLO",6,0))
  // {
  // close_secure(sck);
  // return -5;
  // }
  // char hi[3]={0};
  // size_t rl;
  // byte f;
  // int ret = recv_secure(sck,hi,3,&rl,&f);
  // if(ret<0||strcmp(hi,"HI")!=0)
  // {
  // close_secure(sck);
  // return -6;
  // }
  return sck;
}