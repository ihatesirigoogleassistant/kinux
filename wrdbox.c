#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/un.h>
#define B 4096
#define D(s) do{write(2,s"\n",sizeof(s));_exit(1);}while(0)
#define L(a,b) ((a)<(b)?(a):(b))
static void dl(int c,char**v){
  if(c<4)D("wrdbox dl <url> <out>");
  char*u=v[2],h[256]={0},p[1024]="/",b[B];int port=80,f=0,fd,sk;
  struct timeval tv={30,0};
  if(!strncmp(u,"http://",7))u+=7;
  else if(!strncmp(u,"ftp://",6)){u+=6;port=21;f=1;}
  else D("http/ftp only");
  char*s=strchr(u,'/');if(s){*s=0;int pl=strlen(s+1);strncpy(p,s+1,L(pl,1023));p[L(pl,1023)]=0;}
  s=strchr(u,':');if(s){*s=0;port=atoi(s+1);}
  strncpy(h,u,L(strlen(u),255));h[L(strlen(u),255)]=0;
  struct addrinfo hi,*r;memset(&hi,0,sizeof(hi));hi.ai_family=AF_INET;hi.ai_socktype=SOCK_STREAM;
  char ps[8];snprintf(ps,sizeof(ps),"%d",port);
  if(getaddrinfo(h,ps,&hi,&r))D("host");
  sk=socket(r->ai_family,r->ai_socktype,r->ai_protocol);if(sk<0)D("socket");
  setsockopt(sk,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(sk,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
  if(connect(sk,r->ai_addr,r->ai_addrlen)<0){freeaddrinfo(r);D("connect");}
  freeaddrinfo(r);
  fd=open(v[3],O_WRONLY|O_CREAT|O_TRUNC,0644);if(fd<0)D("open");
  if(f){
    char db[B];int n=read(sk,db,B-1);if(n<0)D("ftp read");db[L(n,B-1)]=0;
    write(sk,"USER anonymous\r\n",16);n=read(sk,db,B-1);
    write(sk,"PASS wrdbox\r\n",13);n=read(sk,db,B-1);
    write(sk,"TYPE I\r\n",8);n=read(sk,db,B-1);
    write(sk,"PASV\r\n",6);n=read(sk,db,B-1);if(n<0)D("pasv read");db[L(n,B-1)]=0;
    char*x=strchr(db,'(');if(!x)D("pasv");x++;
    int p1,p2,p3,p4,p5,p6;
    if(sscanf(x,"%d,%d,%d,%d,%d,%d",&p1,&p2,&p3,&p4,&p5,&p6)!=6)D("pasv parse");
    int ds=socket(AF_INET,SOCK_STREAM,0);
    setsockopt(ds,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(ds,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    struct sockaddr_in da={.sin_family=AF_INET,.sin_port=htons(p5*256+p6)};
    unsigned char*ip=(unsigned char*)&da.sin_addr;
    ip[0]=(unsigned char)p1;ip[1]=(unsigned char)p2;ip[2]=(unsigned char)p3;ip[3]=(unsigned char)p4;
    if(connect(ds,(struct sockaddr*)&da,sizeof(da))<0)D("data conn");
    int l=snprintf(b,B,"RETR %s\r\n",p);write(sk,b,l);
    n=read(sk,db,B-1);if(n<0)D("retr read");db[L(n,B-1)]=0;
    if(strstr(db,"550")||strstr(db,"450"))D("ftp err");
    while((n=read(ds,b,B))>0)write(fd,b,n);
    close(ds);read(sk,db,B-1);
  }else{
    int l=snprintf(b,B,"GET /%s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",p,h);
    write(sk,b,l);int n,hd=1;
    while((n=read(sk,b,B))>0){
      if(hd){
        char*m=memmem(b,n,"\r\n\r\n",4);
        if(m){
          if(memmem(b,m-b,"301",3)||memmem(b,m-b,"302",3)||memmem(b,m-b,"307",3))D("redirect");
          int rl=n-(m+4-b);if(rl>0)write(fd,m+4,rl);hd=0;
        }
      }else write(fd,b,n);
    }
  }
  close(sk);close(fd);
  chmod(v[3],0755);
}
static void sigchld(int s){(void)s;while(waitpid(-1,0,WNOHANG)>0);}
static void run(char*cmd){
  char*a[64],buf[1024];int i=0;char*t;
  int cl=strlen(cmd);strncpy(buf,cmd,L(cl,1023));buf[L(cl,1023)]=0;
  t=strtok(buf," \t\n");
  while(t&&i<63){a[i++]=t;t=strtok(0," \t\n");}a[i]=0;
  if(i<1)return;
  if(!fork()){execvp(a[0],a);_exit(1);}wait(0);
}
static void inits(int c,char**v){
  if(c<3)D("wrdbox inits <file>");
  signal(SIGCHLD,sigchld);
  int fd=open(v[2],O_RDONLY);if(fd<0)D("open");
  char buf[4096],line[1024];int n,li=0,i=0;
  while((n=read(fd,buf,sizeof(buf)))>0){
    for(i=0;i<n;i++){
      if(buf[i]=='\n'){
        if(li>0){line[li]=0;if(line[0]&&line[0]!='#')run(line);li=0;}
      }else if(li<1023)line[li++]=buf[i];
      else{line[1023]=0;run(line);li=0;}
    }
  }
  if(li>0){line[li]=0;if(line[0]&&line[0]!='#')run(line);}
  close(fd);
  while(1)pause();
}
static void cncts(int c,char**v){
  if(c<3)D("wrdbox cncts up|connect|dns|status|list ...");
  int sk=socket(AF_INET,SOCK_DGRAM,0);if(sk<0)D("socket");
  if(!strcmp(v[2],"up")){
    if(c<4)D("wrdbox cncts up <iface>");
    struct ifreq ifr={0};
    strncpy(ifr.ifr_name,v[3],L(strlen(v[3]),IFNAMSIZ-1));ifr.ifr_name[IFNAMSIZ-1]=0;
    ifr.ifr_flags=IFF_UP;
    if(ioctl(sk,SIOCSIFFLAGS,&ifr)<0)D("up");
    if(!fork()){execlp("dhclient","dhclient",v[3],NULL);_exit(1);}wait(0);
  }else if(!strcmp(v[2],"connect")){
    if(c<5)D("wrdbox cncts connect <iface> <ssid> [wpa-pass]");
    struct ifreq ifr={0};
    strncpy(ifr.ifr_name,v[3],L(strlen(v[3]),IFNAMSIZ-1));ifr.ifr_name[IFNAMSIZ-1]=0;
    ifr.ifr_flags=IFF_UP;
    ioctl(sk,SIOCSIFFLAGS,&ifr);
    int wpafd=open("/tmp/wrdbox_wpa.conf",O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(wpafd<0)D("wpa conf");
    dprintf(wpafd,"network={\n  ssid=\"%s\"\n  psk=\"%s\"\n}\n",v[4],c>5?v[5]:"");
    close(wpafd);
    if(!fork()){
      execlp("wpa_supplicant","wpa_supplicant","-B","-i",v[3],"-c","/tmp/wrdbox_wpa.conf",NULL);
      _exit(1);
    }wait(0);
    unlink("/tmp/wrdbox_wpa.conf");
    if(!fork()){execlp("dhclient","dhclient",v[3],NULL);_exit(1);}wait(0);
  }else if(!strcmp(v[2],"dns")){
    if(c<4)D("wrdbox cncts dns <ip>");
    int fd=open("/etc/resolv.conf",O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd<0)D("resolv");
    dprintf(fd,"nameserver %s\n",v[3]);close(fd);
  }else if(!strcmp(v[2],"status")){
    if(c<4)D("wrdbox cncts status <iface>");
    struct ifreq ifr={0};
    strncpy(ifr.ifr_name,v[3],L(strlen(v[3]),IFNAMSIZ-1));ifr.ifr_name[IFNAMSIZ-1]=0;
    if(ioctl(sk,SIOCGIFFLAGS,&ifr)<0)D("status");
    write(1,ifr.ifr_flags&IFF_UP?"UP\n":"DOWN\n",ifr.ifr_flags&IFF_UP?3:5);
    int fd2=socket(AF_INET,SOCK_DGRAM,0);
    ifr.ifr_addr.sa_family=AF_INET;
    if(!ioctl(fd2,SIOCGIFADDR,&ifr)){
      struct sockaddr_in*sin=(struct sockaddr_in*)&ifr.ifr_addr;
      char ip[INET_ADDRSTRLEN];inet_ntop(AF_INET,&sin->sin_addr,ip,sizeof(ip));
      write(1,ip,strlen(ip));write(1,"\n",1);
    }
    close(fd2);
  }else if(!strcmp(v[2],"list")){
    struct if_nameindex*ifs=if_nameindex();if(!ifs)D("if list");
    for(int i=0;ifs[i].if_index;i++){write(1,ifs[i].if_name,strlen(ifs[i].if_name));write(1,"\n",1);}
    if_freenameindex(ifs);
  }
  close(sk);
}
int main(int c,char**v){
  if(c<2)D("wrdbox: dl|inits|cncts");
  if(!strcmp(v[1],"dl"))dl(c,v);
  else if(!strcmp(v[1],"inits"))inits(c,v);
  else if(!strcmp(v[1],"cncts"))cncts(c,v);
  return 0;
}
